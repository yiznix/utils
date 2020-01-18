// Use of this source code is governed by the license that can be found in LICENSE file.
package exec

import (
	"bytes"
	"os/exec"
)

// RunCmd runs the named command with args.
func RunCmd(name, dir string, args ...string) error {
	cmd := exec.Command(name, args...)
	if dir != "" {
		cmd.Dir = dir
	}

	outBuf := new(bytes.Buffer)
	cmd.Stdout = outBuf
	errBuf := new(bytes.Buffer)
	cmd.Stderr = errBuf
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}
