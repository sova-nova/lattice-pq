#include <QApplication>
#include <QIcon>
#include <QMessageBox>

#include "app_style.h"
#include "main_window.h"
#include "platform.h"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName("pq-file-transfer");
    QCoreApplication::setApplicationName("pq-client");
    // Matches packaging/pq-client.desktop, so desktops (KDE and GNOME on Wayland especially) tie this
    // window to the app-menu entry: the taskbar shows its icon and pinning it pins the launcher.
    QGuiApplication::setDesktopFileName("pq-client");
    QIcon icon(":/pq-client.svg");          // sharp at any size when Qt's SVG plugin is present
    icon.addFile(":/pq-client.png");         // and always something without it
    QApplication::setWindowIcon(icon);
    apply_app_style(app);  // the app's own dark look, before any window is made

    if (platform_init() != 0) {
        QMessageBox::critical(nullptr, "Lattice", "Failed to initialize networking.");
        return 1;
    }

    int result = 0;
    {
        MainWindow window;  // destroyed (and its worker joined) before network cleanup
        window.show();
        result = app.exec();
    }

    platform_cleanup();
    return result;
}
