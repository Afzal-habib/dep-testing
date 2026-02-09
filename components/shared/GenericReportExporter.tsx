"use client";

import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Upload, Sheet, FileUp, FileSpreadsheet } from 'lucide-react';
import jsPDF from 'jspdf';
import 'jspdf-autotable';
import * as XLSX from 'xlsx';
import { saveAs } from 'file-saver';

const loadImage = (src: string): Promise<HTMLImageElement> => {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.crossOrigin = 'anonymous';
    img.onload = () => resolve(img);
    img.onerror = reject;
    img.src = src;
  });
};

const loadAndAddLogo = async (doc: jsPDF) => {
  try {
    const logoImg = await loadImage('/566-removebg-preview.png');
    const pageWidth = doc.internal.pageSize.getWidth();
    const imgWidth = 50;
    const imgHeight = (logoImg.height / logoImg.width) * imgWidth;
    const x = (pageWidth - imgWidth) / 2;
    doc.addImage(logoImg, 'PNG', x, 10, imgWidth, imgHeight);
  } catch (error) {
    console.warn('Failed to load logo:', error);
  }
};

const stripHtml = (html: string): string => {
  const tmp = document.createElement('DIV');
  tmp.innerHTML = html;
  return tmp.textContent || tmp.innerText || '';
};

interface ColumnConfig {
  key: string;
  label: string;
  width?: number;
  format?: 'date' | 'percentage' | 'array' | 'object' | 'user' | 'html' | string;
}

interface GenericExportConfig {
  moduleName: 'projects' | 'tasks' | 'users' | 'departments' | 'leads' | 'communications';
  data: any[];
  columns: ColumnConfig[];
  filters?: any;
  templateType: 'standard' | 'detailed' | 'summary' | 'executive';
  moduleSpecificFields?: { [key: string]: any };
  branding?: {
    logo?: string;
    companyName?: string;
    reportTitle?: string;
  };
}

interface ExportResult {
  success: boolean;
  message: string;
  fileName?: string;
}

interface GenericReportExporterProps {
  moduleName: string;
  data: any[];
  onExportComplete?: (result: ExportResult) => void;
}

const GenericReportExporter: React.FC<GenericReportExporterProps> = ({
  moduleName,
  data,
  onExportComplete,
}) => {
  const [selectedTemplate, setSelectedTemplate] = useState('standard');
  const [isExporting, setIsExporting] = useState(false);

  // Dynamic column configuration based on module
  const getModuleColumns = (module: string): ColumnConfig[] => {
    const columnConfigs: { [key: string]: ColumnConfig[] } = {
      departments: [
        { key: 'name', label: 'Department Name', width: 200 },
        { key: 'description', label: 'Description', width: 250, format: 'html' },
        { key: 'status', label: 'Status', width: 100 },
        { key: 'createdAt', label: 'Created', width: 120, format: 'date' },
        { key: 'updatedAt', label: 'Last Updated', width: 120, format: 'date' },
      ],
      projects: [
        { key: 'name', label: 'Project Name', width: 200 },
        { key: 'status', label: 'Status', width: 100 },
        { key: 'progress', label: 'Progress', width: 100, format: 'percentage' },
        { key: 'departments', label: 'Departments', width: 150, format: 'array' },
        { key: 'startDate', label: 'Start Date', width: 120, format: 'date' },
        { key: 'endDate', label: 'End Date', width: 120, format: 'date' },
        { key: 'description', label: 'Description', width: 250, format: 'html' },
        { key: 'requirements', label: 'Requirements', width: 250, format: 'html' },
        { key: 'timeline', label: 'Timeline', width: 250, format: 'html' },
      ],
      tasks: [
        { key: 'title', label: 'Task Title', width: 250 },
        { key: 'status', label: 'Status', width: 100 },
        { key: 'priority', label: 'Priority', width: 100 },
        { key: 'assignee', label: 'Assignee', width: 150, format: 'user' },
        { key: 'dueDate', label: 'Due Date', width: 120, format: 'date' },
        { key: 'department', label: 'Department', width: 150, format: 'object' },
        { key: 'description', label: 'Description', width: 250, format: 'html' },
      ],
      users: [
        { key: 'name', label: 'Full Name', width: 100 },
        { key: 'email', label: 'Email', width: 250 },
        { key: 'role', label: 'Role', width: 250, format: 'object' },
        { key: 'department', label: 'Department', width: 150, format: 'object' },
        { key: 'status', label: 'Status', width: 100 },
      ],
      roles: [
        { key: 'displayName', label: 'Role', width: 100 },
        { key: 'hierarchyLevel', label: 'Hierarchy Level', width: 250 },
        // { key: 'department', label: 'Department', width: 150, format: 'object' },
        { key: 'description', label: 'Description', width: 250, format: 'html' },
        { key: 'status', label: 'Status', width: 100 },
        { key: 'createdAt', label: 'Created', width: 120, format: 'date' },
      ],
      leads: [
        { key: 'name', label: 'Lead Name', width: 200 },
        { key: 'email', label: 'Email', width: 200 },
        { key: 'source', label: 'Source', width: 150 },
        { key: 'status', label: 'Status', width: 100 },
        { key: 'createdAt', label: 'Created', width: 120, format: 'date' },
      ],
      clients: [
        { key: 'name', label: 'Client Name', width: 200 },
        { key: 'email', label: 'Email', width: 200 },
        { key: 'phone', label: 'Phone', width: 200 },
        { key: 'leadId', label: 'Project', width: 150, format: 'object' },
        { key: 'status', label: 'Status', width: 100 },
        { key: 'createdAt', label: 'Created', width: 120, format: 'date' },
      ],
      communications: [
        { key: 'subject', label: 'Subject', width: 250 },
        { key: 'type', label: 'Type', width: 100 },
        { key: 'status', label: 'Status', width: 100 },
        { key: 'sender', label: 'Sender', width: 150 },
        { key: 'createdAt', label: 'Created', width: 120, format: 'date' },
        { key: 'message', label: 'Message', width: 250, format: 'html' },
      ],
      // Analytics-specific configurations
      analytics: [
        { key: 'metric', label: 'Metric', width: 200 },
        { key: 'value', label: 'Value', width: 100 },
        { key: 'category', label: 'Category', width: 150 },
        { key: 'status', label: 'Status', width: 100 },
        { key: 'trend', label: 'Trend', width: 100 },
        { key: 'lastUpdated', label: 'Last Updated', width: 120, format: 'date' },
      ],
      'analytics-departments': [
        { key: 'name', label: 'Department', width: 150 },
        { key: 'totalTasks', label: 'Total Tasks', width: 100 },
        { key: 'completedTasks', label: 'Completed Tasks', width: 100 },
        { key: 'completionRate', label: 'Completion Rate', width: 100, format: 'percentage' },
        { key: 'productivity', label: 'Productivity Score', width: 120 },
        { key: 'teamMembers', label: 'Team Members', width: 100 },
        { key: 'efficiency', label: 'Efficiency', width: 100, format: 'percentage' },
      ],
      'analytics-individuals': [
        { key: 'name', label: 'Team Member', width: 150 },
        { key: 'email', label: 'Email', width: 200 },
        { key: 'role', label: 'Role', width: 120 },
        { key: 'department', label: 'Department', width: 120 },
        { key: 'totalTasks', label: 'Total Tasks', width: 100 },
        { key: 'completedTasks', label: 'Completed Tasks', width: 100 },
        { key: 'completionRate', label: 'Completion Rate', width: 100, format: 'percentage' },
        { key: 'productivity', label: 'Productivity', width: 100 },
        { key: 'efficiency', label: 'Efficiency', width: 100, format: 'percentage' },
      ],
      'analytics-phases': [
        { key: 'title', label: 'Phase Name', width: 200 },
        { key: 'status', label: 'Status', width: 100 },
        { key: 'progress', label: 'Progress', width: 100, format: 'percentage' },
        { key: 'duration', label: 'Planned Duration (days)', width: 130 },
        { key: 'actualDuration', label: 'Actual Duration (days)', width: 130 },
        { key: 'efficiency', label: 'Efficiency', width: 100, format: 'percentage' },
        { key: 'budgetAllocation', label: 'Budget Allocated', width: 120 },
        { key: 'actualCost', label: 'Actual Cost', width: 120 },
        { key: 'budgetVariance', label: 'Budget Variance', width: 120, format: 'percentage' },
        { key: 'isOverdue', label: 'Overdue', width: 80 },
      ],
      'analytics-milestones': [
        { key: 'title', label: 'Milestone Name', width: 200 },
        { key: 'status', label: 'Status', width: 100 },
        { key: 'priority', label: 'Priority', width: 100 },
        { key: 'progress', label: 'Progress', width: 100, format: 'percentage' },
        { key: 'daysUntilDue', label: 'Days Until Due', width: 120 },
        { key: 'linkedTasks', label: 'Linked Tasks', width: 100 },
        { key: 'onTime', label: 'On Time', width: 80 },
        { key: 'isOverdue', label: 'Overdue', width: 80 },
      ],
      'analytics-risks': [
        { key: 'type', label: 'Risk Type', width: 120 },
        { key: 'level', label: 'Risk Level', width: 100 },
        { key: 'description', label: 'Description', width: 250 },
        { key: 'impact', label: 'Impact', width: 200 },
        { key: 'mitigation', label: 'Mitigation', width: 250 },
        { key: 'probability', label: 'Probability', width: 100 },
        { key: 'affectedAreas', label: 'Affected Areas', width: 150, format: 'array' },
      ],
      'analytics-budget': [
        { key: 'category', label: 'Budget Category', width: 150 },
        { key: 'allocated', label: 'Allocated', width: 120 },
        { key: 'actual', label: 'Actual Spent', width: 120 },
        { key: 'variance', label: 'Variance', width: 100, format: 'percentage' },
        { key: 'utilization', label: 'Utilization', width: 100, format: 'percentage' },
        { key: 'remaining', label: 'Remaining', width: 120 },
        { key: 'status', label: 'Status', width: 100 },
      ],
    };
    return columnConfigs[module] || [];
  };

  // Format data based on column format
  const formatCellValue = (value: any, format?: string): string => {
    if (value == null) return '';

    switch (format) {
      case 'date':
        return new Date(value).toLocaleDateString('en-US', {
          year: 'numeric',
          month: 'short',
          day: 'numeric',
        });
      case 'percentage':
        return `${value}%`;
      case 'array':
        return Array.isArray(value) ? value.join(', ') : value;
      case 'object':
        return typeof value === 'object' ? (value.projectName || value.displayName || value.name || value.title || JSON.stringify(value)) : value;
      case 'user':
        return typeof value === 'object' ? (value.displayName || value.name || value.email || '') : value;
      case 'html':
        return stripHtml(String(value));
      default:
        return String(value);
    }
  };

  // Prepare data for export
  const prepareExportData = (columns: ColumnConfig[]) => {
    const headers = columns.map(col => col.label);
    console.log('Export Data:', data);
    const rows = data.map(item =>
      columns.map(col => formatCellValue(item[col.key], col.format))
    );
    console.log('Prepared Export Data:', { headers, rows });
    return { headers, rows };
  };

  // Export to PDF
  const exportToPDF = async () => {
    setIsExporting(true);
    try {
      const columns = getModuleColumns(moduleName);
      const { headers, rows } = prepareExportData(columns);

      // Use A4 landscape for wider page width
      const doc = new jsPDF({ orientation: 'landscape', unit: 'mm', format: 'a4' });
      const pageWidth = doc.internal.pageSize.getWidth();
      const pageHeight = doc.internal.pageSize.getHeight();

      // Add title at top left
      doc.setFontSize(24);
      doc.text(`${moduleName.charAt(0).toUpperCase() + moduleName.slice(1)} Report`, 10, 20);

      // Add logo in center
      await loadAndAddLogo(doc);


      // Use autoTable with better configuration
      let tableRendered = false;
      if (typeof (doc as any).autoTable === 'function') {
        try {
          // Truncate body content to 50 characters
          const truncatedRows = rows.map(row =>
            row.map(cell => cell.length > 50 ? cell.substring(0, 50) + '...' : cell)
          );

          (doc as any).autoTable({
            head: [headers],
            body: truncatedRows,
            startY: 60,
            margin: { left: 8, right: 8, top: 10, bottom: 20 },
            styles: {
              fontSize: 7,
              cellPadding: 2,
              overflow: 'linebreak',
              halign: 'left',
              valign: 'middle',
              lineColor: [220, 220, 220],
              lineWidth: 0.1,
            },
            headStyles: {
              fillColor: [41, 128, 185],
              textColor: 255,
              fontStyle: 'bold',
              lineColor: [41, 128, 185],
              lineWidth: 0.5,
            },
            alternateRowStyles: {
              fillColor: [250, 250, 250],
            },
            bodyStyles: {
              lineColor: [220, 220, 220],
              lineWidth: 0.1,
            },
            columnStyles: columns.reduce((acc, col, idx) => {
              acc[idx] = { cellWidth: 'wrap', cellPadding: [3, 4, 3, 4] };
              return acc;
            }, {} as any),
            didDrawPage: (data: any) => {
              // Footer with page number only
              doc.setFontSize(8);
              doc.text(`Page ${data.pageCount}`, pageWidth - 25, pageHeight - 10);
            },
          });
          tableRendered = true;
        } catch (tableError) {
          console.warn('AutoTable rendering error:', tableError);
          tableRendered = false;
        }
      }

      // Use fallback if autoTable not available or failed
      if (!tableRendered) {
        const colWidth = 55; // Width per column with gap (increased from 40)
        const colGap = 5; // Gap between columns (increased from 3)
        let yPosition = 60;

        // Draw headers
        doc.setFontSize(8);
        doc.setFont('', 'bold');
        headers.forEach((header, idx) => {
          const xPos = 10 + (idx * (colWidth + colGap));
          const headerText = header.length > 50 ? header.substring(0, 50) : header;
          doc.text(headerText, xPos, yPosition);
        });
        doc.setFont('', 'normal');
        yPosition += 8;

        // Draw all rows
        let currentPage = 1;
        rows.forEach((row, rowIdx) => {
          if (yPosition > pageHeight - 20) {
            // Add footer before page break (page number only)
            doc.setFontSize(8);
            doc.text(`Page ${currentPage}`, pageWidth - 25, pageHeight - 10);

            doc.addPage();
            currentPage++;
            yPosition = 15;

            // Re-draw headers on new page
            doc.setFontSize(8);
            doc.setFont('', 'bold');
            headers.forEach((header, idx) => {
              const xPos = 10 + (idx * (colWidth + colGap));
              const headerText = header.length > 50 ? header.substring(0, 50) : header;
              doc.text(headerText, xPos, yPosition);
            });
            doc.setFont('', 'normal');
            yPosition += 8;
          }

          doc.setFontSize(7);
          row.forEach((cell, colIdx) => {
            const xPos = 10 + (colIdx * (colWidth + colGap));
            const text = cell.length > 50 ? cell.substring(0, 50) + '...' : cell;
            doc.text(text, xPos, yPosition);
          });
          yPosition += 6;
        });

        // Add footer to last page
        const totalPages = (doc as any).internal.getNumberOfPages?.() || 1;
        doc.setFontSize(8);
        doc.text(`Generated on: ${new Date().toLocaleDateString()}`, 10, pageHeight - 10);
        doc.text(`Page ${currentPage} of ${totalPages}`, pageWidth - 40, pageHeight - 10);
      }

      const fileName = `${moduleName}_report_${new Date().toISOString().split('T')[0]}.pdf`;
      doc.save(fileName);

      onExportComplete?.({
        success: true,
        message: 'PDF exported successfully',
        fileName,
      });
    } catch (error) {
      console.error('PDF Export Error:', error);
      onExportComplete?.({
        success: false,
        message: `Failed to export PDF: ${error instanceof Error ? error.message : 'Unknown error'}`,
      });
    } finally {
      setIsExporting(false);
    }
  };

  // Export to Excel
  const exportToExcel = async () => {
    setIsExporting(true);
    try {
      const columns = getModuleColumns(moduleName);
      const { headers, rows } = prepareExportData(columns);

      const ws = XLSX.utils.aoa_to_sheet([headers, ...rows]);
      const wb = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb, ws, moduleName);

      const fileName = `${moduleName}_report_${new Date().toISOString().split('T')[0]}.xlsx`;
      XLSX.writeFile(wb, fileName);

      onExportComplete?.({
        success: true,
        message: 'Excel exported successfully',
        fileName,
      });
    } catch (error) {
      onExportComplete?.({
        success: false,
        message: 'Failed to export Excel',
      });
    } finally {
      setIsExporting(false);
    }
  };

  // Export to CSV
  const exportToCSV = async () => {
    setIsExporting(true);
    try {
      const columns = getModuleColumns(moduleName);
      const { headers, rows } = prepareExportData(columns);

      const csvContent = [headers, ...rows]
        .map(row => row.map(cell => `"${cell.replace(/"/g, '""')}"`).join(','))
        .join('\n');

      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const fileName = `${moduleName}_report_${new Date().toISOString().split('T')[0]}.csv`;
      saveAs(blob, fileName);

      onExportComplete?.({
        success: true,
        message: 'CSV exported successfully',
        fileName,
      });
    } catch (error) {
      onExportComplete?.({
        success: false,
        message: 'Failed to export CSV',
      });
    } finally {
      setIsExporting(false);
    }
  };

  const templates = {
    standard: `${moduleName}_standard_report`,
    detailed: `${moduleName}_detailed_analysis`,
    summary: `${moduleName}_executive_summary`,
    executive: `${moduleName}_board_presentation`,
  };

  return (

    // <Button className='bg-red-900' variant="outline">
    <div className=''>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button size='sm' variant="outline" disabled={isExporting || data.length === 0}>
            {isExporting ? 'Exporting...' : <Upload />}
            {/* {isExporting ? 'Exporting...' : 'Upload'} */}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent className='[&>*]:cursor-pointer'>
          <DropdownMenuItem onClick={exportToPDF}><FileUp /> PDF</DropdownMenuItem>
          <DropdownMenuItem onClick={exportToExcel}><Sheet /> Excel</DropdownMenuItem>
          <DropdownMenuItem onClick={exportToCSV}><FileSpreadsheet /> CSV</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      {/* {data.length === 0 && (
        <p className="text-sm text-muted-foreground">No data available for export.</p>
      )} */}

      {/* </Button> */}
    </div>
  );
};

export default GenericReportExporter;