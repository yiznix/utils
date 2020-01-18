// Use of this source code is governed by the license that can be found in LICENSE file.

package image

import (
	"bytes"
	"fmt"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io/ioutil"
	"os"
	"path"
	"strings"

	fileutil "github.com/yiznix/utils/file"
)

func init() {
	image.RegisterFormat("jpeg", "jpeg", jpeg.Decode, jpeg.DecodeConfig)
	image.RegisterFormat("png", "png", png.Decode, png.DecodeConfig)
	image.RegisterFormat("gif", "gif", gif.Decode, gif.DecodeConfig)
}

// IsImage checks the file's extention to determine whether the file is an image type.
// TODO: Add FileType() by checking the file content instead just extension. IsImage() is just one case of it.
func IsImage(filename string) bool {
	return IsImageExt(path.Ext(filename))
}

// IsImageExt checks the file's extention to determine whether the file is an image type.
func IsImageExt(ext string) bool {
	ext = strings.ToLower(ext)
	return ext == ".png" ||
		ext == ".jpg" ||
		ext == ".jpeg" ||
		ext == ".svg" ||
		ext == ".ico" ||
		ext == ".gif" ||
		ext == ".bmp" ||
		ext == ".jfif" ||
		ext == ".tiff"
}

func GetImageFromFile(pth string) (image.Image, string, error) {
	buffer, err := fileutil.GetIOReaderFromFile(pth)
	if err != nil {
		return nil, "", err
	}

	return image.Decode(buffer)
}

type ImageInfo struct {
	Image  image.Image
	Format string
	Config image.Config
	Size   int
}

func GetImageConfig(pth string) (image.Config, string, error) {
	buffer, err := fileutil.GetIOReaderFromFile(pth)
	if err != nil {
		return image.Config{}, "", err
	}

	return image.DecodeConfig(buffer)
}

func GetImageInfo(pth string) (*ImageInfo, error) {
	f, err := os.Open(pth)
	defer f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}

	b := []byte{}
	n, err := f.Read(b)
	if err != nil {
		fmt.Printf("failed to Read byte: %v\n", err)
		return nil, err
	}

	img, format, err := image.Decode(f)
	if err != nil {
		fmt.Printf("Decode image: %+v\n", err)
		return nil, err
	}

	config, _, err := GetImageConfig(pth)
	// config, _, err := image.DecodeConfig(f) // it seems the buffer has been consumed by image.Decode
	if err != nil {
		fmt.Printf("failed to DecodeConfig: %v\n", err)
		return nil, err
	}

	return &ImageInfo{
		Image:  img,
		Format: format,
		Config: config,
		Size:   n,
	}, nil
}

func WriteImageToBytes(img image.Image, format string) ([]byte, error) {
	var err error
	buffer := &bytes.Buffer{}
	switch format {
	case "jpeg":
		err = jpeg.Encode(buffer, img, nil)
	case "png":
		err = png.Encode(buffer, img)
	case "gif":
		err = gif.Encode(buffer, img, nil)
	default:
		err = fmt.Errorf("unsupported format: %s", format)
	}
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func WriteImageToFile(img image.Image, format, pth string, mode os.FileMode) error {
	b, err := WriteImageToBytes(img, format)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(pth, b, mode)
}

// image formats and magic numbers
var magicTable = map[string]string{
	"\xff\xd8\xff":      "image/jpeg",
	"\x89PNG\r\n\x1a\n": "image/png",
	"GIF87a":            "image/gif",
	"GIF89a":            "image/gif",
}

// mimeFromIncipit returns the mime type of an image file from its first few
// bytes or the empty string if the file does not look like a known file type
func MimeFromIncipit(b []byte) string {
	for magic, mime := range magicTable {
		if strings.HasPrefix(string(b), magic) {
			return mime
		}
	}

	return ""
}
