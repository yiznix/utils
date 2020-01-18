// Use of this source code is governed by the license that can be found in LICENSE file.

package file

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"sort"
	"strings"
)

// FileExists checks whether the given file exists.
func FileExists(filename string) (bool, error) {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return true, nil
}

// MaybeMkFile creates a dir with the given name if the file does not exist.
func MaybeMkdir(dirname string, perm os.FileMode) error {
	exists, err := FileExists(dirname)
	if err != nil {
		return err
	}

	if !exists {
		err = os.MkdirAll(dirname, perm)
		if err != nil {
			return err
		}
	}

	return nil
}

// SortLines sorts the lines of th especified src file and save to dest file.
func SortLines(src, dest string) error {
	b, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}
	str := string(b)
	lines := strings.Split(str, "\n")
	newLines := []string{}

	for _, line := range lines {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		newLines = append(newLines, l)
	}
	sort.Strings(newLines)

	f := strings.Join(newLines, "\n")
	return ioutil.WriteFile(dest, []byte(f), 0755)
}

// GetIOReaderFromFile returns io.Reader of the specified file at pth.
func GetIOReaderFromFile(pth string) (io.Reader, error) {
	f, err := ioutil.ReadFile(pth)
	if err != nil {
		return nil, err
	}

	return bytes.NewBuffer(f), nil
}

// CollapseWS collapses consective white spaces to a single one.
func CollapseWS(s string) string {
	lines := strings.Split(s, "\n")
	cleanedLines := []string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		cleanedLines = append(cleanedLines, line)
	}

	return strings.Join(cleanedLines, " ")
}
