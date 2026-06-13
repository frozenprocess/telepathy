// The api module is the vendor-neutral contract (Request/Response schema +
// codecs/diff/assert) shared by the shell and every out-of-process engine. It
// is deliberately tiny — only sigs.k8s.io/yaml — so any engine's module graph
// can import it without dragging in CNI dependencies.
module github.com/frozenprocess/telepathy/api

go 1.25.6

require sigs.k8s.io/yaml v1.6.0
