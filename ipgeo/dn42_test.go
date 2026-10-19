package ipgeo

import (
	"testing"
	"time"

	"github.com/lianyis/dntrace/dn42"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDN42SourceReturnsASNAndMNT(t *testing.T) {
	require.NoError(t, dn42.LoadSnapshot())
	res, err := DN42("172.21.113.130", time.Second, "", false)
	require.NoError(t, err)
	assert.Equal(t, "4242421886", res.Asnumber)
	assert.Equal(t, "LY-MNT", res.Owner)
	assert.Equal(t, "DN42", res.Source)
}

func TestDN42SourceUnknownIP(t *testing.T) {
	require.NoError(t, dn42.LoadSnapshot())
	res, err := DN42("192.0.2.1", time.Second, "", false)
	require.NoError(t, err)
	assert.Empty(t, res.Asnumber)
	assert.Empty(t, res.Owner)
}
