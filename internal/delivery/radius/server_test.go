package radius

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"

	"github.com/identityhub/identityhub/internal/domain"
	usecaseauth "github.com/identityhub/identityhub/internal/usecase/auth"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testKey() [32]byte {
	var k [32]byte
	copy(k[:], "0123456789abcdef0123456789abcdef")
	return k
}

type stubClients struct{}

func (stubClients) Create(_ context.Context, c domain.RADIUSClient) (domain.RADIUSClient, error) {
	return c, nil
}

func (stubClients) ByNASIdentifier(_ context.Context, _ string) (domain.RADIUSClient, error) {
	return domain.RADIUSClient{}, domain.ErrNotFound
}

func (stubClients) Delete(_ context.Context, _ string) error {
	return domain.ErrNotFound
}

func (stubClients) List(_ context.Context, _, _ int) ([]domain.RADIUSClient, int, error) {
	return nil, 0, nil
}

func TestNewValidation(t *testing.T) {
	deps := Deps{Auth: &usecaseauth.Service{}, Clients: nil, Log: testLogger()}
	if _, err := New(Config{Addr: "127.0.0.1:0", EncKey: testKey()}, deps); err == nil {
		t.Error("New without Clients = nil, want error")
	}
	if _, err := New(Config{Addr: "127.0.0.1:0", EncKey: testKey()}, Deps{Clients: nil}); err == nil {
		t.Error("New without Auth = nil, want error")
	}
	if _, err := New(Config{Addr: "", EncKey: testKey()}, Deps{Auth: &usecaseauth.Service{}, Clients: stubClients{}}); err == nil {
		t.Error("New without Addr = nil, want error")
	}
	if _, err := New(Config{Addr: "127.0.0.1:0", EncKey: testKey()}, Deps{Auth: &usecaseauth.Service{}, Clients: stubClients{}}); err != nil {
		t.Errorf("New valid = %v, want success", err)
	}
}

func TestNasHost(t *testing.T) {
	addr, _ := net.ResolveUDPAddr("udp", "10.20.30.40:5678")
	if got := nasHost(addr); got != "10.20.30.40" {
		t.Errorf("nasHost = %q", got)
	}
	if got := nasHost(nil); got != "" {
		t.Errorf("nasHost(nil) = %q, want empty", got)
	}
}

// recordingWriter captures response codes for handler unit tests.
type recordingWriter struct {
	codes []radius.Code
}

func (w *recordingWriter) Write(p *radius.Packet) error {
	w.codes = append(w.codes, p.Code)
	return nil
}

func testPacket(code radius.Code) *radius.Packet {
	return &radius.Packet{Code: code, Identifier: 1, Secret: []byte("test-secret-12")}
}

func TestServeRADIUSIgnoresNonAccessRequest(t *testing.T) {
	s := &Server{}
	for _, code := range []radius.Code{radius.CodeAccountingRequest, radius.CodeStatusServer, radius.CodeAccessAccept} {
		w := &recordingWriter{}
		s.ServeRADIUS(w, &radius.Request{Packet: testPacket(code)})
		if len(w.codes) != 0 {
			t.Errorf("code %v: wrote %v, want silence", code, w.codes)
		}
	}
}

func TestServeRADIUSRejectsWithoutPAP(t *testing.T) {
	s := &Server{}
	p := testPacket(radius.CodeAccessRequest)
	if err := rfc2865.UserName_SetString(p, "ara"); err != nil {
		t.Fatal(err)
	}
	w := &recordingWriter{}
	s.ServeRADIUS(w, &radius.Request{Packet: p, RemoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 6000}})
	if len(w.codes) != 1 || w.codes[0] != radius.CodeAccessReject {
		t.Errorf("codes = %v, want single Access-Reject", w.codes)
	}
}
