package com.innova.analyzer.core.export

import android.content.ContentValues
import android.content.Context
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.util.Log
import android.widget.Toast
import com.innova.analyzer.data.models.NetworkEvent
import com.innova.analyzer.ui.report.AppSummary
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object PdfExporter {

    // Helper to format bytes inside the PDF generator
    private fun formatBytes(bytes: Long): String {
        val mb = bytes / (1024.0 * 1024.0)
        return if (mb >= 1.0) {
            String.format(Locale.US, "%.2f MB", mb)
        } else {
            val kb = bytes / 1024.0
            if (kb >= 1.0) {
                String.format(Locale.US, "%.1f KB", kb)
            } else {
                "$bytes B"
            }
        }
    }

    fun generateAndDownloadPdf(
        context: Context,
        summaries: List<AppSummary>,
        allLogs: List<NetworkEvent>,
        totalBlocked: Int,
        topApp: String
    ) {
        Toast.makeText(context, "Generating Forensic Report...", Toast.LENGTH_SHORT).show()

        // Run on background thread so we don't freeze the UI while drawing hundreds of pages
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val pdfDocument = PdfDocument()
                // Standard A4 Size (595 x 842)
                val pageInfo = PdfDocument.PageInfo.Builder(595, 842, 1).create()

                var page = pdfDocument.startPage(pageInfo)
                var canvas = page.canvas

                // ==========================================
                // PAINT BRUSH SETUP
                // ==========================================
                val titlePaint = Paint().apply { typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD); textSize = 20f; color = Color.BLACK }
                val subtitlePaint = Paint().apply { typeface = Typeface.create(Typeface.DEFAULT, Typeface.ITALIC); textSize = 12f; color = Color.DKGRAY }
                val headerPaint = Paint().apply { typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD); textSize = 14f; color = Color.rgb(33, 150, 243) } // Primary Blue
                val textPaint = Paint().apply { typeface = Typeface.create(Typeface.DEFAULT, Typeface.NORMAL); textSize = 11f; color = Color.BLACK }
                val threatPaint = Paint().apply { typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD); textSize = 11f; color = Color.RED }
                val linePaint = Paint().apply { color = Color.LTGRAY; strokeWidth = 1f }

                // Monospace paints for the raw logs
                val monoPaint = Paint().apply { typeface = Typeface.create(Typeface.MONOSPACE, Typeface.NORMAL); textSize = 8f; color = Color.DKGRAY }
                val monoThreatPaint = Paint().apply { typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD); textSize = 8f; color = Color.RED }

                val margin = 40f
                val usableWidth = pageInfo.pageWidth - (margin * 2)
                var yPos = margin + 20f

                // Helper function to handle page breaks dynamically
                fun checkPageBreak(requiredSpace: Float) {
                    if (yPos + requiredSpace > 800f) {
                        pdfDocument.finishPage(page)
                        page = pdfDocument.startPage(pageInfo)
                        canvas = page.canvas
                        yPos = margin + 20f
                    }
                }

                // ==========================================
                // PAGE 1: EXECUTIVE SUMMARY
                // ==========================================
                canvas.drawText("INNOVA ANALYZER - NETWORK FORENSIC REPORT", margin, yPos, titlePaint)
                yPos += 20f
                val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.getDefault())
                canvas.drawText("Generated automatically on: ${dateFormat.format(Date())}", margin, yPos, subtitlePaint)
                yPos += 30f

                canvas.drawLine(margin, yPos, margin + usableWidth, yPos, linePaint)
                yPos += 30f

                // High-Level Stats
                canvas.drawText("EXECUTIVE OVERVIEW", margin, yPos, headerPaint)
                yPos += 20f
                canvas.drawText("• Total Packets Intercepted: ${allLogs.size}", margin, yPos, textPaint)
                yPos += 15f
                canvas.drawText("• Total Active Threats Blocked: $totalBlocked", margin, yPos, if (totalBlocked > 0) threatPaint else textPaint)
                yPos += 15f
                canvas.drawText("• Highest Bandwidth Consumer: $topApp", margin, yPos, textPaint)
                yPos += 30f

                // App Breakdown
                canvas.drawText("APPLICATION PRIVACY ASSESSMENT", margin, yPos, headerPaint)
                yPos += 25f

                // Draw Table Header
                canvas.drawText("GRADE", margin, yPos, textPaint)
                canvas.drawText("APPLICATION", margin + 60f, yPos, textPaint)
                canvas.drawText("DATA USED", margin + 250f, yPos, textPaint)
                canvas.drawText("THREATS", margin + 350f, yPos, textPaint)
                yPos += 10f
                canvas.drawLine(margin, yPos, margin + usableWidth, yPos, linePaint)
                yPos += 20f

                summaries.forEach { app ->
                    checkPageBreak(30f)

                    val gradeText = "[ ${app.scoreBreakdown.grade} ]"
                    val nameText = app.appName.take(25).padEnd(25)
                    val dataText = formatBytes(app.totalBytes)
                    val threatText = if (app.threats > 0) "${app.threats} Blocked" else "Clean"

                    val paintToUse = if (app.threats > 0) threatPaint else textPaint

                    canvas.drawText(gradeText, margin, yPos, paintToUse)
                    canvas.drawText(nameText, margin + 60f, yPos, paintToUse)
                    canvas.drawText(dataText, margin + 250f, yPos, paintToUse)
                    canvas.drawText(threatText, margin + 350f, yPos, paintToUse)

                    yPos += 18f
                }

                yPos += 30f
                canvas.drawLine(margin, yPos, margin + usableWidth, yPos, linePaint)
                yPos += 40f

                // Force a page break before the raw logs begin
                checkPageBreak(800f)

                // ==========================================
                // PAGE 2+: PCAPDROID-STYLE RAW PACKET LOGS
                // ==========================================
                canvas.drawText("RAW CONNECTION LOGS (PCAP-STYLE HEX DUMP)", margin, yPos, headerPaint)
                yPos += 20f

                val logHeader = "FORMAT: [TIMESTAMP] [PROTO] [APP] SOURCE_IP:PORT -> DEST_IP:PORT (DOMAIN) | BYTES | STATUS"
                canvas.drawText(logHeader, margin, yPos, monoPaint)
                yPos += 15f
                canvas.drawLine(margin, yPos, margin + usableWidth, yPos, linePaint)
                yPos += 20f

                val timeFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault())

                // Draw every single packet in chronological order (oldest to newest)
                allLogs.reversed().forEach { log ->
                    checkPageBreak(15f) // Small required space since font is tiny

                    val time = timeFormat.format(Date(log.timestamp))
                    val proto = log.protocol.name.padEnd(5)
                    val app = (log.appName ?: "System").take(12).padEnd(12)

                    val src = "${log.sourceIp}:${log.sourcePort}".padEnd(21)
                    val dest = "${log.destIp}:${log.destPort}".padEnd(21)
                    val domain = log.domain?.let { "($it)" }?.take(30)?.padEnd(30) ?: "".padEnd(30)

                    val bytes = "${log.totalBytes} B".padStart(8)
                    val status = if (log.isSuspicious) "[BLOCKED]" else "[ALLOWED]"

                    // Combine into a technical, perfectly aligned string
                    val logLine = "[$time] [$proto] $app | $src -> $dest $domain | $bytes | $status"

                    if (log.isSuspicious) {
                        canvas.drawText(logLine, margin, yPos, monoThreatPaint)
                    } else {
                        canvas.drawText(logLine, margin, yPos, monoPaint)
                    }
                    yPos += 10f // Tighter line spacing for logs
                }

                pdfDocument.finishPage(page)

                // ==========================================
                // SAVE FILE TO DOWNLOADS FOLDER (Scoped Storage)
                // ==========================================
                val fileName = "Innova_Security_Report_${System.currentTimeMillis()}.pdf"
                val resolver = context.contentResolver

                val contentValues = ContentValues().apply {
                    put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
                    put(MediaStore.MediaColumns.MIME_TYPE, "application/pdf")
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                    }
                }

                val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
                if (uri != null) {
                    resolver.openOutputStream(uri)?.use { outputStream ->
                        pdfDocument.writeTo(outputStream)
                    }
                    withContext(Dispatchers.Main) {
                        Toast.makeText(context, "✅ Report downloaded successfully to your files!", Toast.LENGTH_LONG).show()
                    }
                } else {
                    throw Exception("Failed to create file in MediaStore.")
                }

                pdfDocument.close()

            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(context, "❌ Failed to generate PDF: ${e.message}", Toast.LENGTH_LONG).show()
                }
                Log.e("PdfExporter", "Error generating PDF", e)
            }
        }
    }
}