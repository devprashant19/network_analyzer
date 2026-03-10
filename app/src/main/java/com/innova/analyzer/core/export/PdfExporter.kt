package com.innova.analyzer.core.export

import android.content.Context
import android.widget.Toast
import com.innova.analyzer.data.models.NetworkEvent
import com.innova.analyzer.ui.report.AppSummary

object PdfExporter {
    fun generateAndDownloadPdf(
        context: Context,
        summaries: List<AppSummary>,
        allLogs: List<NetworkEvent>,
        totalBlocked: Int,
        topApp: String
    ) {
        // Placeholder for PDF generation logic
        Toast.makeText(context, "PDF Export feature is coming soon!", Toast.LENGTH_SHORT).show()
    }
}
