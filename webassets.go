package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
)

// webAsset is one file of the interface, held in memory with a tag derived
// from its contents.
type webAsset struct {
	data        []byte
	etag        string
	contentType string
}

var (
	webAssets  = map[string]webAsset{}
	buildStamp string
)

// loadWebAssets reads the embedded interface once at startup and gives each
// file an ETag.
//
// http.FileServer over an embedded filesystem sends neither Last-Modified nor
// ETag, because embedded files carry a zero timestamp. A browser then has
// nothing to revalidate against and is free to keep serving its cached copy,
// so a new build could ship a fixed layout that never reaches the screen.
func loadWebAssets(root fs.FS) {
	digest := sha256.New()

	err := fs.WalkDir(root, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := fs.ReadFile(root, name)
		if err != nil {
			return err
		}

		sum := sha256.Sum256(data)
		tag := `"` + hex.EncodeToString(sum[:8]) + `"`

		contentType := mime.TypeByExtension(path.Ext(name))
		if contentType == "" {
			contentType = "application/octet-stream"
		}

		webAssets[name] = webAsset{data: data, etag: tag, contentType: contentType}
		digest.Write(sum[:])
		return nil
	})
	if err != nil {
		log.Fatalf("Error reading the embedded interface: %v", err)
	}

	whole := digest.Sum(nil)
	buildStamp = hex.EncodeToString(whole[:4])
	log.Printf("Interface build %s (%d files)", buildStamp, len(webAssets))
}

// serveWebAsset serves the interface with validators, so a browser picks up a
// new build immediately instead of showing a cached copy.
func serveWebAsset(c *gin.Context) {
	name := strings.TrimPrefix(path.Clean("/"+c.Param("filepath")), "/")
	if name == "" || name == "." {
		name = "index.html"
	}

	asset, ok := webAssets[name]
	if !ok {
		c.Status(http.StatusNotFound)
		return
	}

	// "no-cache" does not mean "do not store": it means ask first. Combined
	// with the ETag, an unchanged file costs one small 304 and a changed one
	// arrives straight away.
	c.Header("Cache-Control", "no-cache")
	c.Header("ETag", asset.etag)

	if match := c.GetHeader("If-None-Match"); match != "" {
		for _, candidate := range strings.Split(match, ",") {
			if strings.TrimSpace(candidate) == asset.etag {
				c.Status(http.StatusNotModified)
				return
			}
		}
	}

	c.Data(http.StatusOK, asset.contentType, asset.data)
}
