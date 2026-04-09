package main

import (
	"github.com/carlos7ags/folio/document"
	"github.com/carlos7ags/folio/html"
)

func main() {
	doc := document.NewDocument(document.PageSizeA4)
	elems, _ := html.Convert(`
<ol>
   <li>This is a <strong>test<br />to see</strong> if it breaks</li>
</ol>`, nil)
	for _, e := range elems {
		doc.Add(e)
	}
	doc.Save("test.pdf")
}
