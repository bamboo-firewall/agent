package iptables

type option func(*Table)

func WithIPFamily(family int) option {
	return func(t *Table) {
		t.ipVersion = family
	}
}

func WithLockSecondsTimeout(timeout int) option {
	return func(t *Table) {
		if timeout <= 0 {
			timeout = defaultLockSecondTimeout
		}
		t.lockSecondTimeout = timeout
	}
}
