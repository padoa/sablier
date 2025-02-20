package docker

import (
	"context"
	"errors"
	"fmt"
	"github.com/sablierapp/sablier/app/discovery"
	"github.com/sablierapp/sablier/app/providers"
	"io"
	"strings"

	"github.com/docker/docker/api/types/container"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/sablierapp/sablier/app/instance"
	log "github.com/sirupsen/logrus"
)

// Interface guard
var _ providers.Provider = (*DockerClassicProvider)(nil)

type DockerClassicProvider struct {
	Client          client.APIClient
	desiredReplicas int32
}

func NewDockerClassicProvider() (*DockerClassicProvider, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("cannot create docker client: %v", err)
	}

	serverVersion, err := cli.ServerVersion(context.Background())
	if err != nil {
		return nil, fmt.Errorf("cannot connect to docker host: %v", err)
	}

	log.Tracef("connection established with docker %s (API %s)", serverVersion.Version, serverVersion.APIVersion)

	return &DockerClassicProvider{
		Client:          cli,
		desiredReplicas: 1,
	}, nil
}

func (provider *DockerClassicProvider) GetGroups(ctx context.Context) (map[string][]string, error) {
	args := filters.NewArgs()
	args.Add("label", fmt.Sprintf("%s=true", discovery.LabelEnable))

	containers, err := provider.Client.ContainerList(ctx, container.ListOptions{
		All:     true,
		Filters: args,
	})

	if err != nil {
		return nil, err
	}

	groups := make(map[string][]string)
	for _, c := range containers {
		groupName := c.Labels[discovery.LabelGroup]
		if len(groupName) == 0 {
			groupName = discovery.LabelGroupDefaultValue
		}
		group := groups[groupName]
		group = append(group, strings.TrimPrefix(c.Names[0], "/"))
		groups[groupName] = group
	}

	log.Debug(fmt.Sprintf("%v", groups))

	return groups, nil
}

func (provider *DockerClassicProvider) Start(ctx context.Context, name string) error {
	return provider.Client.ContainerStart(ctx, name, container.StartOptions{})
}

func (provider *DockerClassicProvider) Stop(ctx context.Context, name string) error {
	return provider.Client.ContainerStop(ctx, name, container.StopOptions{})
}

func (provider *DockerClassicProvider) GetState(ctx context.Context, name string) (instance.State, error) {
	spec, err := provider.Client.ContainerInspect(ctx, name)
	if err != nil {
		return instance.State{}, err
	}

	// "created", "running", "paused", "restarting", "removing", "exited", or "dead"
	switch spec.State.Status {
	case "created", "paused", "restarting", "removing":
		return instance.NotReadyInstanceState(name, 0, provider.desiredReplicas), nil
	case "running":
		if spec.State.Health != nil {
			// // "starting", "healthy" or "unhealthy"
			if spec.State.Health.Status == "healthy" {
				return instance.ReadyInstanceState(name, provider.desiredReplicas), nil
			} else if spec.State.Health.Status == "unhealthy" {
				if len(spec.State.Health.Log) >= 1 {
					lastLog := spec.State.Health.Log[len(spec.State.Health.Log)-1]
					return instance.UnrecoverableInstanceState(name, fmt.Sprintf("container is unhealthy: %s (%d)", lastLog.Output, lastLog.ExitCode), provider.desiredReplicas), nil
				} else {
					return instance.UnrecoverableInstanceState(name, "container is unhealthy: no log available", provider.desiredReplicas), nil
				}
			} else {
				return instance.NotReadyInstanceState(name, 0, provider.desiredReplicas), nil
			}
		}
		return instance.ReadyInstanceState(name, provider.desiredReplicas), nil
	case "exited":
		if spec.State.ExitCode != 0 {
			return instance.UnrecoverableInstanceState(name, fmt.Sprintf("container exited with code \"%d\"", spec.State.ExitCode), provider.desiredReplicas), nil
		}
		return instance.NotReadyInstanceState(name, 0, provider.desiredReplicas), nil
	case "dead":
		return instance.UnrecoverableInstanceState(name, "container in \"dead\" state cannot be restarted", provider.desiredReplicas), nil
	default:
		return instance.UnrecoverableInstanceState(name, fmt.Sprintf("container status \"%s\" not handled", spec.State.Status), provider.desiredReplicas), nil
	}
}

func (provider *DockerClassicProvider) NotifyInstanceStopped(ctx context.Context, instance chan<- string) {
	msgs, errs := provider.Client.Events(ctx, types.EventsOptions{
		Filters: filters.NewArgs(
			filters.Arg("scope", "local"),
			filters.Arg("type", string(events.ContainerEventType)),
			filters.Arg("event", "die"),
		),
	})
	for {
		select {
		case msg, ok := <-msgs:
			if !ok {
				log.Error("provider event stream is closed")
				return
			}
			// Send the container that has died to the channel
			instance <- strings.TrimPrefix(msg.Actor.Attributes["name"], "/")
		case err, ok := <-errs:
			if !ok {
				log.Error("provider event stream is closed", err)
				return
			}
			if errors.Is(err, io.EOF) {
				log.Debug("provider event stream closed")
				return
			}
			log.Error("provider event stream error", err)
		case <-ctx.Done():
			return
		}
	}
}
