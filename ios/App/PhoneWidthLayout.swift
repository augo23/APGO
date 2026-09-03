import SwiftUI

// On iPad the system gives a sheet (and the main window) far more width than a
// phone, which stretched these Form rows across the screen — the layout App
// Review flagged on an 11" iPad. Constraining the content to a phone-width
// column and centering it keeps every screen visually identical to the iPhone
// build at any iPad size or orientation. Compact width (iPhone) is untouched.
struct PhoneWidthLayout: ViewModifier {
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass

    // Roughly the width of a large iPhone, which is what these Forms were
    // designed against.
    private let maxContentWidth: CGFloat = 430

    func body(content: Content) -> some View {
        if horizontalSizeClass == .regular {
            HStack(spacing: 0) {
                Spacer(minLength: 0)
                content.frame(maxWidth: maxContentWidth)
                Spacer(minLength: 0)
            }
            .background(Color(.systemGroupedBackground).ignoresSafeArea())
        } else {
            content
        }
    }
}

extension View {
    /// Keeps a screen at iPhone proportions when running in a regular-width
    /// (iPad) environment.
    func phoneWidthLayout() -> some View { modifier(PhoneWidthLayout()) }
}
