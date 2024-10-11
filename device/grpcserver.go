package device

import (
	"net"
	"sync"

	pb "golang.zx2c4.com/wireguard/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type EventServer struct {
	wg                    sync.WaitGroup
	PeerSeenEventCh       chan *pb.PeerSeenEvent
	PeerSeenEventWatchers map[string]chan *pb.PeerSeenEvent
	watchersMtx           sync.RWMutex
	log                   *Logger
	pb.UnimplementedEventEmitterServer
}

func (g *EventServer) Emit(e *emptypb.Empty, srv pb.EventEmitter_EmitServer) error {
	ch := make(chan *pb.PeerSeenEvent, 5)
	g.watchersMtx.RLock()
	g.PeerSeenEventWatchers["t"] = ch
	g.watchersMtx.RUnlock()
	defer func() {
		g.watchersMtx.RLock()
		delete(g.PeerSeenEventWatchers, "t")
		g.watchersMtx.RUnlock()
		close(ch)
	}()

	for {
		select {
		case <-srv.Context().Done():
			return nil
		case event := <-ch:
			if s, ok := status.FromError(srv.Send(event)); ok {
				switch s.Code() {
				case codes.OK:
					// noop
				case codes.Unavailable, codes.Canceled, codes.DeadlineExceeded:
					g.log.Verbosef("client terminated connection\n")
					return nil
				default:
					g.log.Verbosef("failed to send to client %q", s.Err())
					return nil
				}
			}
		}
	}
}

func (g *EventServer) Run(listenAddr string) error {
	srv := grpc.NewServer()
	pb.RegisterEventEmitterServer(srv, g)
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "server unable to bind on provided host")
	}
	g.wg.Add(1)
	go func() {
		g.log.Verbosef("Starting gRPC server on %q", listenAddr)
		err := srv.Serve(l)
		if err != nil {
			g.log.Errorf("server unable to serve: %q", err)
		}
		g.wg.Done()
	}()
	go g.EventBroadcaster()
	g.wg.Wait()
	close(g.PeerSeenEventCh)
	srv.GracefulStop()
	return nil
}

func (g *EventServer) EventBroadcaster() {
	for event := range g.PeerSeenEventCh {
		g.watchersMtx.RLock()

		for _, w := range g.PeerSeenEventWatchers {
			select {
			case w <- event:
			default:
				g.log.Verbosef("grpc client stream full, dropping messages")
			}
		}
		g.watchersMtx.RUnlock()
	}
}
