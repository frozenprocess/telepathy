// engines/cilium is a standalone module that builds the Cilium provider as its
// own binary over Cilium's untouched source tree (../../third_party/cilium),
// using Cilium's native dependency versions. Building it separately from the
// Calico-backed shell is what avoids the cross-CNI dependency conflicts (eBPF,
// envoy, controller-runtime); deps resolve via the sibling go.work, mirroring
// the root module's pattern.
module github.com/frozenprocess/telepathy/engines/cilium

go 1.26.4
