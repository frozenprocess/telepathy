// engines/antrea is a standalone module that builds the Antrea provider as its
// own binary over Antrea's untouched source tree (../../third_party/antrea),
// using Antrea's native dependency versions. Building it separately from the
// Calico-backed shell is what avoids the cross-CNI dependency conflicts
// (network-policy-api, controller-runtime); deps resolve via the sibling
// go.work, mirroring the root module's pattern.
module github.com/frozenprocess/telepathy/engines/antrea

go 1.25.6
