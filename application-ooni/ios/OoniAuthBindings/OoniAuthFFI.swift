import Foundation

@_silgen_name("ooniauth_run_basic_usage")
private func ooniauth_run_basic_usage() -> UnsafeMutablePointer<CChar>?

@_silgen_name("ooniauth_run_benchmarks")
private func ooniauth_run_benchmarks() -> UnsafeMutablePointer<CChar>?

@_silgen_name("ooniauth_string_free")
private func ooniauth_string_free(_ ptr: UnsafeMutablePointer<CChar>?)

enum OoniAuthFFI {
    static func runBasicUsage() -> String {
        guard let raw = ooniauth_run_basic_usage() else {
            return "error: FFI returned null pointer"
        }
        defer { ooniauth_string_free(raw) }
        return String(cString: raw)
    }

    static func runBenchmarks() -> String {
        guard let raw = ooniauth_run_benchmarks() else {
            return "error: FFI returned null pointer"
        }
        defer { ooniauth_string_free(raw) }
        return String(cString: raw)
    }
}
