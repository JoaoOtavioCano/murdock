package blocklistapi

import (
	"testing"
)

func TestIsInPasswordsBlocklist(t *testing.T) {
	client := NewHaveIBeenPwnedAPIClient()
	is, err := client.IsInPasswordsBlocklist("password")
	if err != nil {
		t.Error(err.Error())
	}

	if !is {
		t.Error("password should be in the block list")
	}
}
