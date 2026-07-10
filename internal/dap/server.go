package dap

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/v1/debug"

	"github.com/open-policy-agent/regal/internal/util"
)

type Server struct {
	Listener net.Listener
	Logger   *DebugLogger
	Addr     string
	Port     int
}

// NewServer creates a new debug server that listens for incoming connections on addr,
// represented as "host:port". If the port is missing or 0, a random port will be picked.
func NewServer(addr string, logger *DebugLogger) *Server {
	return &Server{Addr: addr, Logger: logger, Port: parsePort(addr)}
}

func (s *Server) Start(ctx context.Context) (err error) {
	lc := &net.ListenConfig{}
	if s.Listener, err = lc.Listen(ctx, "tcp4", s.Addr); err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	s.Port = parsePort(s.Listener.Addr().String())
	s.Logger.Local.Info("starting dap server on localhost:%d", s.Port)

	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			return fmt.Errorf("could not accept: %w", err)
		}

		s.Logger.Local.Info("New connection from %s", conn.RemoteAddr())

		protoManager := NewProtocolManager(s.Logger.Local)
		s.Logger.ProtocolManager = protoManager

		state := NewState(protoManager, debug.NewDebugger(
			debug.SetEventHandler(NewEventHandler(protoManager)),
			debug.SetLogger(s.Logger),
		), s.Logger)

		if err := protoManager.Start(ctx, conn, state.HandleMessage); err != nil {
			s.Logger.Local.Error("Failed to handle connection: %v", err)
		}
	}
}

func (s *Server) Close() (err error) {
	if s.Listener != nil {
		err = s.Listener.Close()
	}

	return util.WrapErr(err, "failed to close debug server")
}

func parsePort(addr string) (port int) {
	if strings.Contains(addr, ":") {
		port, _ = strconv.Atoi(strings.Split(addr, ":")[1])
	}

	return port
}

func NewEventHandler(pm *ProtocolManager) debug.EventHandler {
	return func(e debug.Event) {
		switch e.Type {
		case debug.ExceptionEventType:
			pm.SendEvent(NewStoppedExceptionEvent(e.Thread, e.Message))
		case debug.StdoutEventType:
			pm.SendEvent(NewOutputEvent("stdout", e.Message))
		case debug.StoppedEventType:
			pm.SendEvent(NewStoppedEvent(e.Message, e.Thread, nil, "", ""))
		case debug.TerminatedEventType:
			pm.SendEvent(NewTerminatedEvent())
		case debug.ThreadEventType:
			pm.SendEvent(NewThreadEvent(e.Thread, e.Message))
		}
	}
}
