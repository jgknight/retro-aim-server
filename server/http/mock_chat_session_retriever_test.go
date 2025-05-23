// Code generated by mockery v2.53.3. DO NOT EDIT.

package http

import (
	state "github.com/mk6i/retro-aim-server/state"
	mock "github.com/stretchr/testify/mock"
)

// mockChatSessionRetriever is an autogenerated mock type for the ChatSessionRetriever type
type mockChatSessionRetriever struct {
	mock.Mock
}

type mockChatSessionRetriever_Expecter struct {
	mock *mock.Mock
}

func (_m *mockChatSessionRetriever) EXPECT() *mockChatSessionRetriever_Expecter {
	return &mockChatSessionRetriever_Expecter{mock: &_m.Mock}
}

// AllSessions provides a mock function with given fields: cookie
func (_m *mockChatSessionRetriever) AllSessions(cookie string) []*state.Session {
	ret := _m.Called(cookie)

	if len(ret) == 0 {
		panic("no return value specified for AllSessions")
	}

	var r0 []*state.Session
	if rf, ok := ret.Get(0).(func(string) []*state.Session); ok {
		r0 = rf(cookie)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*state.Session)
		}
	}

	return r0
}

// mockChatSessionRetriever_AllSessions_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AllSessions'
type mockChatSessionRetriever_AllSessions_Call struct {
	*mock.Call
}

// AllSessions is a helper method to define mock.On call
//   - cookie string
func (_e *mockChatSessionRetriever_Expecter) AllSessions(cookie interface{}) *mockChatSessionRetriever_AllSessions_Call {
	return &mockChatSessionRetriever_AllSessions_Call{Call: _e.mock.On("AllSessions", cookie)}
}

func (_c *mockChatSessionRetriever_AllSessions_Call) Run(run func(cookie string)) *mockChatSessionRetriever_AllSessions_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *mockChatSessionRetriever_AllSessions_Call) Return(_a0 []*state.Session) *mockChatSessionRetriever_AllSessions_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockChatSessionRetriever_AllSessions_Call) RunAndReturn(run func(string) []*state.Session) *mockChatSessionRetriever_AllSessions_Call {
	_c.Call.Return(run)
	return _c
}

// newMockChatSessionRetriever creates a new instance of mockChatSessionRetriever. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func newMockChatSessionRetriever(t interface {
	mock.TestingT
	Cleanup(func())
}) *mockChatSessionRetriever {
	mock := &mockChatSessionRetriever{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
