package store

import (
	"errors"
	"github.com/go-webauthn/webauthn/webauthn"
	"sync"
)

type Providers struct {
	User SessionProvider
}

type UserProvider interface {
	Get(name string) (user *UserSession, err error)
	Set(user *UserSession) (err error)
}

type UserSession struct {
	Cookie   string
	User     User
	Mac      string
	Webauthn *webauthn.SessionData
}

type SessionProvider struct {
	users map[string]UserSession
	mutex sync.RWMutex
}

func NewSessionProvider() *SessionProvider {
	return &SessionProvider{
		users: map[string]UserSession{},
		mutex: sync.RWMutex{},
	}
}

func (p *SessionProvider) Set(user *UserSession) (err error) {
	p.mutex.Lock()

	defer p.mutex.Unlock()

	if user.Cookie == "" {
		return errors.New("user has no cookie")
	}

	p.users[user.Cookie] = *user

	return nil
}

func (p *SessionProvider) Get(cookie string) (user *UserSession, err error) {
	p.mutex.RLock()

	defer p.mutex.RUnlock()

	var (
		ok bool
		u  UserSession
	)

	if u, ok = p.users[cookie]; !ok {
		return nil, errors.New("could not find user")
	}

	return &u, nil
}
