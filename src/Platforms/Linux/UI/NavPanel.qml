import QtQuick
import QtQuick.Controls

Drawer {
    id: drawer
    width: 0.66 * window.width
    height: window.height

    Label {
        text: "Content goes here!"
        anchors.centerIn: parent
    }
}