package iptables

import (
	"bytes"
	"fmt"
)

// RestoreBuilder build iptables data
// example:
/*
*filter
:TEST_CHAIN - [0:0]
-A TEST_CHAIN -m comment --comment "test chain"
-A TEST_CHAIN -j ACCEPT
COMMIT
*/
type RestoreBuilder struct {
	buf       bytes.Buffer
	tableName string
	isWriting bool
}

func (b *RestoreBuilder) IsEmpty() bool {
	return b.buf.Len() == 0
}

func (b *RestoreBuilder) Reset() {
	b.buf.Reset()
	b.tableName = ""
	b.isWriting = false
}

func (b *RestoreBuilder) StartTransaction(tableName string) {
	b.tableName = tableName
	b.isWriting = false
}

func (b *RestoreBuilder) startTransaction() {
	if !b.isWriting {
		b.writeFormattedLine(fmt.Sprintf("*%s", b.tableName))
		b.isWriting = true
	}
}

func (b *RestoreBuilder) EndTransaction() {
	if b.isWriting {
		b.writeFormattedLine("COMMIT")
	}
	b.tableName = ""
	b.isWriting = false
}

func (b *RestoreBuilder) WriteChain(chainName string) {
	b.startTransaction()
	b.writeFormattedLine(fmt.Sprintf(":%s - [0:0]", chainName))
}

func (b *RestoreBuilder) WriteRule(rule string) {
	b.startTransaction()
	b.writeFormattedLine(rule)
}

func (b *RestoreBuilder) writeFormattedLine(formatted string) {
	b.buf.WriteString(formatted)
	b.buf.WriteByte('\n')
}
