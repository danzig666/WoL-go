package main

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gin-gonic/gin"
)

func withTestWebAssets(t *testing.T) {
	t.Helper()

	previousAssets := webAssets
	previousStamp := buildStamp
	root := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte(
			`<link href="style.css?v=__WOL_BUILD__"><script src="app.js?v=__WOL_BUILD__"></script>`,
		)},
		"app.js":    &fstest.MapFile{Data: []byte(`console.log("current")`)},
		"style.css": &fstest.MapFile{Data: []byte(`body { color: white; }`)},
	}
	loadWebAssets(fs.FS(root))
	t.Cleanup(func() {
		webAssets = previousAssets
		buildStamp = previousStamp
	})
}

func testAssetRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/web/*filepath", serveWebAsset)
	return router
}

func TestIndexIsNotStoredAndReferencesVersionedAssets(t *testing.T) {
	withTestWebAssets(t)
	router := testAssetRouter()

	request := httptest.NewRequest(http.MethodGet, "/web/index.html", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("index returned %d", response.Code)
	}
	if cache := response.Header().Get("Cache-Control"); !strings.Contains(cache, "no-store") {
		t.Errorf("index Cache-Control is %q, want no-store", cache)
	}
	body := response.Body.String()
	if strings.Contains(body, buildStampPlaceholder) {
		t.Error("build placeholder was left in index.html")
	}
	if !strings.Contains(body, "style.css?v="+buildStamp) ||
		!strings.Contains(body, "app.js?v="+buildStamp) {
		t.Errorf("index does not reference build %s: %s", buildStamp, body)
	}
}

func TestVersionedAssetsAreImmutableButOldURLsRevalidate(t *testing.T) {
	withTestWebAssets(t)
	router := testAssetRouter()

	request := httptest.NewRequest(http.MethodGet, "/web/app.js?v="+buildStamp, nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if cache := response.Header().Get("Cache-Control"); !strings.Contains(cache, "immutable") {
		t.Errorf("versioned asset Cache-Control is %q, want immutable", cache)
	}

	request = httptest.NewRequest(http.MethodGet, "/web/app.js", nil)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if cache := response.Header().Get("Cache-Control"); !strings.Contains(cache, "no-cache") || strings.Contains(cache, "immutable") {
		t.Errorf("unversioned asset Cache-Control is %q, want revalidation", cache)
	}
}

func TestAPIResponsesAreNeverCached(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(securityHeaders())
	router.GET("/api/config", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"build": "test"})
	})

	request := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if cache := response.Header().Get("Cache-Control"); cache != "no-store" {
		t.Errorf("API Cache-Control is %q, want no-store", cache)
	}
}
