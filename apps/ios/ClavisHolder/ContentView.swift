import SwiftUI

struct ContentView: View {
    private let profileText: String?

    init() {
        profileText = ContentView.readLinkedProfile()
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Согласие")
                    .font(.largeTitle)
                Text("Запрос этой сессии")
                    .font(.title2)
                if let profileText {
                    Text(profileText)
                        .font(.body)
                        .multilineTextAlignment(.leading)
                        .textSelection(.enabled)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(24)
        }
    }

    /// Calls `clavis_profile`. A negative count means the strong symbol is not linked yet.
    private static func readLinkedProfile() -> String? {
        let capacity = 4096
        var buffer = [UInt8](repeating: 0, count: capacity)
        let count = buffer.withUnsafeMutableBufferPointer { pointer -> Int32 in
            guard let base = pointer.baseAddress else {
                return -1
            }
            return clavis_profile(base, pointer.count)
        }
        guard count > 0 else {
            return nil
        }
        var length = min(Int(count), buffer.count)
        while length > 0, buffer[length - 1] == 0 {
            length -= 1
        }
        guard length > 0 else {
            return nil
        }
        let text = String(decoding: buffer.prefix(length), as: UTF8.self)
        guard !text.isEmpty else {
            return nil
        }
        return text
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
