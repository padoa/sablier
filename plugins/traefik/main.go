package traefik

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
)

type SablierMiddleware struct {
	client      *http.Client
	request     *http.Request
	next        http.Handler
	useRedirect bool
	skipOnFail  bool
}

// New function creates the configuration
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	req, err := config.BuildRequest(name)
	if err != nil {
		return nil, err
	}

	return &SablierMiddleware{
		request: req,
		client:  &http.Client{},
		next:    next,
		// there is no way to make blocking work in traefik without redirect so let's make it default
		useRedirect: config.Blocking != nil,
		skipOnFail:  config.SkipOnFail,
	}, nil
}

func (sm *SablierMiddleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger := createLogger(true)
	sablierRequest := sm.request.Clone(context.TODO())

	resp, err := sm.client.Do(sablierRequest)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	if sm.skipOnFail && resp.StatusCode >= 500 {
		logger.Warn("Sablier has skipped the error")
		sm.next.ServeHTTP(rw, req)
		return
	}

	defer resp.Body.Close()

	conditonalResponseWriter := newResponseWriter(rw)

	useRedirect := false

	if resp.Header.Get("X-Sablier-Session-Status") == "ready" {
		// Check if the backend already received request data
		trace := &httptrace.ClientTrace{
			WroteHeaders: func() {
				conditonalResponseWriter.ready = true
			},
			WroteRequest: func(info httptrace.WroteRequestInfo) {
				conditonalResponseWriter.ready = true
			},
		}
		newCtx := httptrace.WithClientTrace(req.Context(), trace)
		sm.next.ServeHTTP(conditonalResponseWriter, req.WithContext(newCtx))
		useRedirect = sm.useRedirect
	}

	if conditonalResponseWriter.ready == false {
		conditonalResponseWriter.ready = true
		if useRedirect {
			conditonalResponseWriter.Header().Set("Location", req.URL.String())

			status := http.StatusFound
			if req.Method != http.MethodGet {
				status = http.StatusTemporaryRedirect
			}

			conditonalResponseWriter.WriteHeader(status)
			_, err := conditonalResponseWriter.Write([]byte(http.StatusText(status)))
			if err != nil {
				http.Error(conditonalResponseWriter, err.Error(), http.StatusInternalServerError)
			}
		} else {
			conditonalResponseWriter.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
			io.Copy(conditonalResponseWriter, resp.Body)
		}
	}
}

func newResponseWriter(rw http.ResponseWriter) *responseWriter {
	return &responseWriter{
		responseWriter: rw,
		headers:        make(http.Header),
	}
}

type responseWriter struct {
	responseWriter http.ResponseWriter
	headers        http.Header
	ready          bool
}

func (r *responseWriter) Header() http.Header {
	if r.ready {
		return r.responseWriter.Header()
	}
	return r.headers
}

func (r *responseWriter) Write(buf []byte) (int, error) {
	if r.ready == false {
		return len(buf), nil
	}
	return r.responseWriter.Write(buf)
}

func (r *responseWriter) WriteHeader(code int) {
	if r.ready == false && code == http.StatusServiceUnavailable {
		// We get a 503 HTTP Status Code when there is no backend server in the pool
		// to which the request could be sent.  Also, note that r.ready
		// will never return false in case there was a connection established to
		// the backend server and so we can be sure that the 503 was produced
		// inside Traefik already
		return
	}

	headers := r.responseWriter.Header()
	for header, value := range r.headers {
		headers[header] = value
	}

	r.responseWriter.WriteHeader(code)
}

func (r *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := r.responseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("%T is not a http.Hijacker", r.responseWriter)
	}
	return hijacker.Hijack()
}

func (r *responseWriter) Flush() {
	if flusher, ok := r.responseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

const pluginName = "sablier"

func createLogger(isDebugModeEnabled bool) *slog.Logger {
	loggerOpts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	if isDebugModeEnabled {
		loggerOpts.Level = slog.LevelDebug
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, loggerOpts)).With("plugin", pluginName)
}
