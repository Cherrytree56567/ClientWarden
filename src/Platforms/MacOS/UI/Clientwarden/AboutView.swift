import SwiftUI

struct AboutView: View {
    var appName: String {
        Bundle.main.infoDictionary?["CFBundleName"] as? String ?? "ClientWarden"
    }
    var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
    }
    var buildNumber: String {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"
    }
    
    @State private var easterEggs = 0
    @State private var easterCount = 0
    
    var body: some View {
        VStack(spacing: 12) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .frame(width: 96, height: 96)
                .rotationEffect(.degrees(Double(easterEggs) * 360))
                .animation(.easeInOut(duration: 0.6), value: easterEggs)
                .padding(.top, 24)
                .onTapGesture {
                    easterCount += 1
                    if (easterCount >= 3) {
                        easterEggs += 1
                        easterCount = 0
                    }
                }

            Text("ClientWarden")
                .font(.title2)
                .fontWeight(.bold)

            Text("Version \(appVersion) (\(buildNumber))")
                .font(.caption)
                .foregroundStyle(.secondary)

            Spacer()
            
            HStack {
                Link("GitHub", destination: URL(string: "https://github.com/Cherrytree56567/ClientWarden")!)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .foregroundStyle(.link.opacity(087))
                    .font(.caption)
                    .padding(8)
                
                Spacer()
                
                Text("Made By CT5")
                    .frame(maxWidth: .infinity, alignment: .trailing)
                    .foregroundStyle(.gray)
                    .font(.caption)
                    .padding(8)
            }
        }
        .frame(minWidth: 300, maxWidth: 300, minHeight: 400, maxHeight: 400, alignment: .top)
    }
}

#Preview {
    AboutView()
}
