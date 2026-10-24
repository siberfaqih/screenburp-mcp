package net.portswigger.mcp.evidence

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.ui.editor.EditorOptions
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dimension
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import javax.imageio.ImageIO
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JSplitPane
import javax.swing.SwingUtilities

data class NativeCaptureResult(
    val png: ByteArray,
    val width: Int,
    val height: Int,
    val requestSearchApplied: String?,
    val responseSearchApplied: String?,
    val redacted: Boolean,
    val requestCaret: CaretPlacement? = null,
    val responseCaret: CaretPlacement? = null,
    val placedBoxes: List<PlacedBox> = emptyList(),
    val boxNotes: List<String> = emptyList(),
)

/** Outcome of requesting a native editor scroll via caret placement. */
data class CaretPlacement(
    val requested: Int,
    val applied: Int,
    val verified: Boolean,
)

/**
 * Mode B: renders Burp's *native* HTTP message editors and captures their
 * actual Swing pixels. No HTML, CSS, browser renderer, or custom editor is
 * involved at any point.
 *
 * The editors hold the full HTTP message; the PNG shows the visible
 * viewport only. Callers must surface [VIEWPORT_NOTE] in their summary and
 * must never claim the whole message is visible.
 */
object NativeEditorCapture {
    const val VIEWPORT_NOTE =
        "Viewport capture: the PNG shows the visible editor viewport only, " +
            "not the entire HTTP message. The full message remains in the editor."

    /** Builds the request/response container. Exposed for headless-safe tests. */
    fun buildSplitPane(
        requestComponent: Component,
        responseComponent: Component,
        layout: CaptureLayout,
    ): JSplitPane = JSplitPane(
        if (layout == CaptureLayout.SIDE_BY_SIDE) JSplitPane.HORIZONTAL_SPLIT else JSplitPane.VERTICAL_SPLIT,
        requestComponent,
        responseComponent,
    ).apply {
        resizeWeight = 0.5
        isContinuousLayout = true
    }

    /**
     * Lays out [component] at [width]x[height] and paints its real Swing
     * pixels into a [BufferedImage]. Always executes on the Event Dispatch
     * Thread, so it is safe to call from MCP handler threads.
     */
    fun paintToImage(component: JComponent, width: Int, height: Int): BufferedImage {
        NativeEvidence.requireValidDimensions(width, height)
        return runOnEdt {
            val size = Dimension(width, height)
            component.preferredSize = size
            component.size = size
            component.validate()
            component.doLayout()
            // Proportional divider only takes effect once the split pane has a size.
            findSplitPane(component)?.setDividerLocation(0.5)
            component.validate()
            component.doLayout()
            val image = BufferedImage(width, height, BufferedImage.TYPE_INT_RGB)
            val graphics = image.createGraphics()
            graphics.color = component.background
            graphics.fillRect(0, 0, width, height)
            component.paint(graphics)
            graphics.dispose()
            image
        }
    }

    fun encodePng(image: BufferedImage): ByteArray {
        val output = ByteArrayOutputStream()
        check(ImageIO.write(image, "png", output)) { "No PNG writer is available in this Java runtime" }
        return output.toByteArray()
    }

    /**
     * Production path: creates Burp's native editors via the Montoya API,
     * populates them with the exact [request]/[response] objects, applies the
     * user's Burp theme, mounts them side by side (or stacked), and captures
     * the real pixels.
     *
     * [requestCaret]/[responseCaret] are message-text offsets the editors are
     * asked to scroll to via caret placement (the only programmatic scroll
     * mechanism the Montoya API exposes). Placement is verified by reading
     * the caret back; check [CaretPlacement.verified] and offer assisted
     * manual capture when it fails.
     */
    fun capture(
        api: MontoyaApi,
        request: HttpRequest,
        response: HttpResponse?,
        width: Int,
        height: Int,
        layout: CaptureLayout,
        requestSearch: String? = null,
        responseSearch: String? = null,
        requestCaret: Int? = null,
        responseCaret: Int? = null,
        boxTargets: List<BoxTarget> = emptyList(),
    ): NativeCaptureResult {
        // Realize the hierarchy in an off-screen, focus-free window so the
        // editors create peers and build any lazily-created UI. Skipped only
        // when headless (unit tests with mocked editors); Burp itself always
        // runs with a display.
        val realized = !java.awt.GraphicsEnvironment.isHeadless()
        // Phase 1: create editors and load content. Burp applies content
        // updates through the EDT queue, so anything queued here (including
        // Burp-internal refresh tasks) runs before phase 2 is dispatched.
        class Setup(
            val requestEditor: burp.api.montoya.ui.editor.HttpRequestEditor,
            val responseEditor: burp.api.montoya.ui.editor.HttpResponseEditor?,
            val container: JPanel,
            val split: JSplitPane,
            val host: javax.swing.JWindow?,
        )
        val setup = runOnEdt {
            val ui = api.userInterface()
            val requestEditor = ui.createHttpRequestEditor(EditorOptions.READ_ONLY)
            requestEditor.setRequest(request)
            val responseEditor = if (response != null) {
                ui.createHttpResponseEditor(EditorOptions.READ_ONLY).also { it.setResponse(response) }
            } else null
            val responseComponent: Component =
                responseEditor?.uiComponent() ?: JPanel(BorderLayout()).apply {
                    add(JLabel("<No response>"), BorderLayout.CENTER)
                }
            val split = buildSplitPane(requestEditor.uiComponent(), responseComponent, layout)
            val container = JPanel(BorderLayout()).apply { add(split, BorderLayout.CENTER) }
            ui.applyThemeToComponent(container)
            // Realize the hierarchy in an off-screen, focus-free window so the
            // editors create peers and build any lazily-created UI. The window
            // never appears on screen and never takes focus.
            val host = if (realized) {
                javax.swing.JWindow().apply {
                    setFocusableWindowState(false)
                    setAutoRequestFocus(false)
                    location = java.awt.Point(-10000, -10000)
                }.also {
                    container.preferredSize = Dimension(width, height)
                    it.add(container)
                    it.pack()
                    it.isVisible = true
                }
            } else null
            Setup(requestEditor, responseEditor, container, split, host)
        }
        // Phase 2 runs after every task queued by phase 1, so the editors
        // hold their content before search/caret/layout/paint run.
        try {
            return runOnEdt {
            if (!requestSearch.isNullOrBlank()) setup.requestEditor.setSearchExpression(requestSearch)
            val requestPlacement = requestCaret?.let {
                applyCaret(setup.requestEditor, request.toString().length, it)
            }
            var responsePlacement: CaretPlacement? = null
            if (setup.responseEditor != null && response != null) {
                if (!responseSearch.isNullOrBlank()) setup.responseEditor.setSearchExpression(responseSearch)
                responsePlacement = responseCaret?.let {
                    applyCaret(setup.responseEditor, response.toString().length, it)
                }
            }

            val size = Dimension(width, height)
            setup.container.preferredSize = size
            setup.container.size = size
            setup.container.validate()
            setup.container.doLayout()
            setup.split.setDividerLocation(0.5)
            setup.container.validate()
            setup.container.doLayout()

            // Box placement runs here: the realized hierarchy is alive and the
            // painted pixels below come from this exact layout, so coordinates
            // translate 1:1 into the capture.
            val placement = if (boxTargets.isEmpty()) {
                BoxPlacement(emptyList(), emptyList())
            } else {
                BoundingBox.placeBoxes(
                    setup.requestEditor.uiComponent(), request.toString(),
                    if (response != null) setup.responseEditor?.uiComponent() else null,
                    response?.toString(),
                    setup.container, width, height, boxTargets,
                )
            }

            val image = BufferedImage(width, height, BufferedImage.TYPE_INT_RGB)
            val graphics = image.createGraphics()
            graphics.color = setup.container.background
            graphics.fillRect(0, 0, width, height)
            setup.container.paint(graphics)
            graphics.dispose()

            NativeCaptureResult(
                png = encodePng(image),
                width = width,
                height = height,
                requestSearchApplied = requestSearch?.takeIf { it.isNotBlank() },
                responseSearchApplied = responseSearch?.takeIf { it.isNotBlank() && response != null },
                redacted = false,
                requestCaret = requestPlacement,
                responseCaret = responsePlacement,
                placedBoxes = placement.boxes,
                boxNotes = placement.notes,
            )
        }
        } finally {
            setup.host?.let { host -> runOnEdt { host.dispose() } }
        }
    }

    /**
     * Asks a native editor to scroll to [requested] (a message-text offset)
     * via caret placement and verifies by reading the caret back. The
     * Montoya API exposes no selection setters and no viewport accessors,
     * so caret read-back is the strongest available scroll signal.
     */
    fun applyCaret(
        editor: burp.api.montoya.ui.editor.Editor,
        messageLength: Int,
        requested: Int,
    ): CaretPlacement {
        val clamped = requested.coerceIn(0, messageLength)
        editor.setCaretPosition(clamped)
        val actual = editor.caretPosition()
        return CaretPlacement(requested, actual, actual == clamped)
    }

    private fun findSplitPane(component: Component): JSplitPane? {
        if (component is JSplitPane) return component
        if (component is java.awt.Container) {
            for (child in component.components) {
                findSplitPane(child)?.let { return it }
            }
        }
        return null
    }

    private fun <T> runOnEdt(block: () -> T): T {
        if (SwingUtilities.isEventDispatchThread()) return block()
        var result: T? = null
        var failure: Throwable? = null
        SwingUtilities.invokeAndWait {
            try {
                result = block()
            } catch (t: Throwable) {
                failure = t
            }
        }
        failure?.let { throw it as? RuntimeException ?: RuntimeException(it) }
        @Suppress("UNCHECKED_CAST")
        return result as T
    }
}
