package net.portswigger.mcp.evidence

import java.awt.AWTException
import java.awt.Frame
import java.awt.GraphicsEnvironment
import java.awt.IllegalComponentStateException
import java.awt.Rectangle
import java.awt.Robot
import java.awt.image.BufferedImage

/**
 * Mode A: captures the actual on-screen Burp Suite Repeater pixels with
 * [java.awt.Robot]. The Repeater UI is never reconstructed.
 *
 * Known Montoya limitation: the API exposes no Repeater window or tab
 * enumeration ([burp.api.montoya.repeater.Repeater] only offers
 * `sendToRepeater`), so the capture region must be given explicitly or
 * derived from the Burp suite frame bounds. The caller is responsible for
 * bringing the intended Repeater tab to the foreground first. If the region
 * cannot be captured, an explicit error is returned instead of a substitute
 * image.
 */
object RepeaterCapture {
    fun captureRectangle(x: Int, y: Int, width: Int, height: Int): BufferedImage {
        require(width in 1..NativeEvidence.MAX_WIDTH) {
            "Region width $width is out of range 1-${NativeEvidence.MAX_WIDTH}."
        }
        require(height in 1..NativeEvidence.MAX_HEIGHT) {
            "Region height $height is out of range 1-${NativeEvidence.MAX_HEIGHT}."
        }
        if (GraphicsEnvironment.isHeadless()) {
            throw UnsupportedOperationException(
                "Repeater capture requires a display, but Burp is running headless. " +
                    "Bring Burp Suite to the foreground with a visible Repeater tab and retry."
            )
        }
        val robot = try {
            Robot()
        } catch (e: AWTException) {
            throw UnsupportedOperationException(
                "Repeater capture is unavailable: no screen-capture device (${e.message})."
            )
        } catch (e: SecurityException) {
            throw UnsupportedOperationException(
                "Repeater capture was denied by the security manager (${e.message})."
            )
        }
        return robot.createScreenCapture(Rectangle(x, y, width, height))
    }

    /** Captures the full Burp suite frame. Fails explicitly when not visible. */
    fun captureSuiteFrame(frame: Frame): BufferedImage {
        if (!frame.isShowing) {
            throw IllegalArgumentException(
                "Burp Suite window is not visible on screen. Bring Burp to the " +
                    "foreground with the intended Repeater tab selected, then retry. " +
                    "Alternatively pass an explicit region_x/region_y/region_width/region_height."
            )
        }
        val location = try {
            frame.locationOnScreen
        } catch (e: IllegalComponentStateException) {
            throw IllegalArgumentException(
                "Burp Suite window position is unavailable (${e.message}). " +
                    "Bring Burp to the foreground and retry."
            )
        }
        return captureRectangle(location.x, location.y, frame.width, frame.height)
    }
}
