Imports System
Imports System.IO
Imports System.Diagnostics
Imports System.Drawing
Imports System.Text
Imports System.Text.RegularExpressions
Imports System.Windows.Forms
Imports System.Media
Imports System.Reflection

Public Class Form1
    Inherits Form

    '==================== CAMPOS ====================
    Private WithEvents txtEmail As TextBox
    Private WithEvents btnAnalyze As Button
    Private WithEvents btnLoadEml As Button
    Private WithEvents btnClear As Button
    Private WithEvents btnExample As Button

    Private WithEvents lstIndicators As ListBox
    Private lblVerdict As Label
    Private lblScore As Label
    Private lblSkull As Label
    Private picSkull As PictureBox
    Private resultPanel As GradientPanel

    Private statusStrip As StatusStrip
    Private stPython As ToolStripStatusLabel
    Private stVB As ToolStripStatusLabel
    Private stSpring As ToolStripStatusLabel
    Private stTime As ToolStripStatusLabel

    Private stopwatch As Stopwatch = New Stopwatch()
    Private soundPlayer As New SoundPlayer()

    ' Rutas relativas para los sonidos
    Private ReadOnly SOUND_SAFE As String = Path.Combine("sounds", "safe.wav")
    Private ReadOnly SOUND_WARNING As String = Path.Combine("sounds", "warning.wav")
    Private ReadOnly SOUND_DANGER As String = Path.Combine("sounds", "danger.wav")

    '==================== INICIO ====================
    Public Sub New()
        MyBase.New()
        Me.DoubleBuffered = True
        Me.Text = "Ciberseguridad para Todos - Detector de Phishing"
        Me.StartPosition = FormStartPosition.CenterScreen
        Me.MinimumSize = New Size(1000, 750)
        Me.BackColor = Color.FromArgb(245, 245, 245)
        Me.Font = New Font("Segoe UI", 9.0F, FontStyle.Regular)

        BuildUi()
    End Sub

    Protected Overrides Sub OnLoad(e As EventArgs)
        MyBase.OnLoad(e)
        CheckPythonStatus()
    End Sub

    '==================== UI ====================
    Private Sub BuildUi()
        ' Encabezado
        Dim header As New Panel With {
            .Dock = DockStyle.Top,
            .Height = 70,
            .BackColor = Color.FromArgb(0, 64, 107)
        }
        Dim title As New Label With {
            .Text = "Ciberseguridad para Todos",
            .AutoSize = True,
            .ForeColor = Color.White,
            .Font = New Font("Segoe UI", 18, FontStyle.Bold),
            .Location = New Point(20, 10)
        }
        Dim subtitle As New Label With {
            .Text = "Detectando Correos Maliciosos con Python y VB.NET",
            .AutoSize = True,
            .ForeColor = Color.FromArgb(220, 230, 240),
            .Font = New Font("Segoe UI", 10, FontStyle.Regular),
            .Location = New Point(22, 45)
        }
        header.Controls.Add(title)
        header.Controls.Add(subtitle)
        Controls.Add(header)

        ' Panel principal con márgenes uniformes
        Dim mainPanel As New Panel With {
            .Dock = DockStyle.Fill,
            .Padding = New Padding(20),
            .BackColor = Color.Transparent
        }
        Controls.Add(mainPanel)

        ' Layout principal 2 columnas
        Dim grid As New TableLayoutPanel With {
            .Dock = DockStyle.Fill,
            .ColumnCount = 2,
            .RowCount = 2
        }
        grid.ColumnStyles.Add(New ColumnStyle(SizeType.Percent, 50.0F))
        grid.ColumnStyles.Add(New ColumnStyle(SizeType.Percent, 50.0F))
        grid.RowStyles.Add(New RowStyle(SizeType.Percent, 60.0F))
        grid.RowStyles.Add(New RowStyle(SizeType.Percent, 40.0F))
        grid.Margin = New Padding(0)
        mainPanel.Controls.Add(grid)

        ' ---------- Columna izquierda: Entrada ----------
        Dim grpEntrada As New GroupBox With {
            .Text = "Entrada de Correo",
            .Dock = DockStyle.Fill,
            .Margin = New Padding(0, 0, 10, 10),
            .Padding = New Padding(10)
        }
        txtEmail = New TextBox With {
            .Multiline = True,
            .ScrollBars = ScrollBars.Vertical,
            .Dock = DockStyle.Fill,
            .Font = New Font("Consolas", 10.0F),
            .BorderStyle = BorderStyle.FixedSingle,
            .Margin = New Padding(0, 0, 0, 10)
        }
        Dim leftPanel As New TableLayoutPanel With {
            .Dock = DockStyle.Fill,
            .RowCount = 2,
            .Margin = New Padding(0)
        }
        leftPanel.RowStyles.Add(New RowStyle(SizeType.Percent, 85.0F))
        leftPanel.RowStyles.Add(New RowStyle(SizeType.Percent, 15.0F))

        ' Botonera
        Dim btnPanel As New FlowLayoutPanel With {
            .Dock = DockStyle.Fill,
            .FlowDirection = FlowDirection.LeftToRight,
            .Padding = New Padding(0),
            .Margin = New Padding(0)
        }
        btnAnalyze = New Button With {
            .Text = "Analizar Correo",
            .Width = 120,
            .Height = 32,
            .BackColor = Color.FromArgb(0, 122, 204),
            .ForeColor = Color.White,
            .FlatStyle = FlatStyle.Flat,
            .Margin = New Padding(0, 0, 10, 0)
        }
        btnAnalyze.FlatAppearance.BorderSize = 0

        btnLoadEml = New Button With {
            .Text = "Cargar EML",
            .Width = 100,
            .Height = 32,
            .BackColor = Color.FromArgb(106, 176, 76),
            .ForeColor = Color.White,
            .FlatStyle = FlatStyle.Flat,
            .Margin = New Padding(0, 0, 10, 0)
        }
        btnLoadEml.FlatAppearance.BorderSize = 0

        btnExample = New Button With {
            .Text = "Ejemplo",
            .Width = 80,
            .Height = 32,
            .BackColor = Color.FromArgb(76, 86, 106),
            .ForeColor = Color.White,
            .FlatStyle = FlatStyle.Flat,
            .Margin = New Padding(0, 0, 10, 0)
        }
        btnExample.FlatAppearance.BorderSize = 0

        btnClear = New Button With {
            .Text = "Limpiar",
            .Width = 80,
            .Height = 32,
            .BackColor = Color.FromArgb(208, 68, 72),
            .ForeColor = Color.White,
            .FlatStyle = FlatStyle.Flat
        }
        btnClear.FlatAppearance.BorderSize = 0

        btnPanel.Controls.Add(btnAnalyze)
        btnPanel.Controls.Add(btnLoadEml)
        btnPanel.Controls.Add(btnExample)
        btnPanel.Controls.Add(btnClear)

        leftPanel.Controls.Add(txtEmail, 0, 0)
        leftPanel.Controls.Add(btnPanel, 0, 1)
        grpEntrada.Controls.Add(leftPanel)
        grid.Controls.Add(grpEntrada, 0, 0)
        grid.SetRowSpan(grpEntrada, 2)

        ' ---------- Columna derecha (arriba): Resultado ----------
        Dim grpResultado As New GroupBox With {
            .Text = "Resultado del Análisis",
            .Dock = DockStyle.Fill,
            .Margin = New Padding(10, 0, 0, 10),
            .Padding = New Padding(10)
        }

        resultPanel = New GradientPanel() With {
            .Dock = DockStyle.Fill,
            .Padding = New Padding(15),
            .ColorTop = Color.FromArgb(35, 35, 40),
            .ColorBottom = Color.FromArgb(75, 30, 30)
        }

        lblVerdict = New Label With {
            .Text = "VEREDICTO: ESPERANDO ANÁLISIS",
            .AutoSize = False,
            .TextAlign = ContentAlignment.MiddleCenter,
            .Dock = DockStyle.Top,
            .Height = 36,
            .Font = New Font("Segoe UI", 14, FontStyle.Bold),
            .ForeColor = Color.Gainsboro,
            .Margin = New Padding(0, 0, 0, 10)
        }
        lblScore = New Label With {
            .Text = "Puntuación: 0/10",
            .AutoSize = False,
            .TextAlign = ContentAlignment.MiddleCenter,
            .Dock = DockStyle.Top,
            .Height = 26,
            .Font = New Font("Segoe UI", 10, FontStyle.Regular),
            .ForeColor = Color.Silver,
            .Margin = New Padding(0, 0, 0, 15)
        }

        ' Calavera: usa imagen si existe; si no, emoji
        picSkull = New PictureBox With {
            .SizeMode = PictureBoxSizeMode.Zoom,
            .Dock = DockStyle.Fill,
            .Visible = False,
            .Margin = New Padding(20)
        }
        Dim skullPath As String = Path.Combine(Application.StartupPath, "skull.png")
        If File.Exists(skullPath) Then
            picSkull.Image = Image.FromFile(skullPath)
            picSkull.Visible = True
        End If

        lblSkull = New Label With {
            .Text = "💀",
            .Dock = DockStyle.Fill,
            .TextAlign = ContentAlignment.MiddleCenter,
            .Font = New Font("Segoe UI Emoji", 100, FontStyle.Regular),
            .ForeColor = Color.FromArgb(240, 70, 70),
            .Visible = Not picSkull.Visible,
            .Margin = New Padding(20)
        }

        resultPanel.Controls.Add(lblSkull)
        resultPanel.Controls.Add(picSkull)
        resultPanel.Controls.Add(lblScore)
        resultPanel.Controls.Add(lblVerdict)
        grpResultado.Controls.Add(resultPanel)
        grid.Controls.Add(grpResultado, 1, 0)

        ' ---------- Columna derecha (abajo): Indicadores ----------
        Dim grpIndicadores As New GroupBox With {
            .Text = "Indicadores Detectados",
            .Dock = DockStyle.Fill,
            .Margin = New Padding(10, 10, 0, 0),
            .Padding = New Padding(10)
        }
        lstIndicators = New ListBox With {
            .Dock = DockStyle.Fill,
            .BorderStyle = BorderStyle.FixedSingle,
            .DrawMode = DrawMode.OwnerDrawFixed,
            .ItemHeight = 22,
            .BackColor = Color.White
        }
        AddHandler lstIndicators.DrawItem, AddressOf lstIndicators_DrawItem
        grpIndicadores.Controls.Add(lstIndicators)
        grid.Controls.Add(grpIndicadores, 1, 1)

        ' ---------- Barra de estado ----------
        statusStrip = New StatusStrip With {
            .Dock = DockStyle.Bottom,
            .SizingGrip = False,
            .Padding = New Padding(20, 5, 20, 5)
        }
        stPython = New ToolStripStatusLabel("Python Engine Inactive")
        stVB = New ToolStripStatusLabel("VB.NET UI Framework")
        stSpring = New ToolStripStatusLabel() With {.Spring = True}
        stTime = New ToolStripStatusLabel("Tiempo de análisis: 0.0s")

        statusStrip.Items.AddRange(New ToolStripItem() {
            stPython,
            New ToolStripStatusLabel("  |  "),
            stVB,
            stSpring,
            stTime
        })
        Controls.Add(statusStrip)

        ' ---------- Eventos ----------
        AddHandler btnAnalyze.Click, AddressOf BtnAnalyze_Click
        AddHandler btnLoadEml.Click, AddressOf BtnLoadEml_Click
        AddHandler btnClear.Click, AddressOf BtnClear_Click
        AddHandler btnExample.Click, AddressOf BtnExample_Click
    End Sub

    '======== DIBUJO LISTBOX (viñetas rojas + texto) ========
    Private Sub lstIndicators_DrawItem(sender As Object, e As DrawItemEventArgs)
        e.DrawBackground()
        If e.Index < 0 Then Return

        Dim txt As String = lstIndicators.Items(e.Index).ToString()
        Dim g = e.Graphics
        Dim bulletRect As New Rectangle(e.Bounds.X + 8, e.Bounds.Y + (e.Bounds.Height \ 2) - 4, 8, 8)
        Using b As New SolidBrush(Color.FromArgb(220, 60, 60))
            g.FillEllipse(b, bulletRect)
        End Using

        Dim textX As Integer = e.Bounds.X + 24
        Using br As New SolidBrush(If((e.State And DrawItemState.Selected) = DrawItemState.Selected, Color.White, Color.Black))
            g.DrawString(txt, Me.Font, br, textX, e.Bounds.Y + 2)
        End Using

        If (e.State And DrawItemState.Selected) = DrawItemState.Selected Then
            Using p As New Pen(Color.FromArgb(0, 122, 204))
                g.DrawRectangle(p, e.Bounds.X, e.Bounds.Y, e.Bounds.Width - 1, e.Bounds.Height - 1)
            End Using
        End If
        e.DrawFocusRectangle()
    End Sub

    '==================== LÓGICA ====================
    Private Sub BtnAnalyze_Click(sender As Object, e As EventArgs)
        Dim emailContent As String = txtEmail.Text
        If String.IsNullOrWhiteSpace(emailContent) Then
            MessageBox.Show("Por favor, ingrese el contenido del correo electrónico para analizar.", "Advertencia",
                            MessageBoxButtons.OK, MessageBoxIcon.Warning)
            Return
        End If

        Try
            Cursor.Current = Cursors.WaitCursor
            btnAnalyze.Enabled = False
            stTime.Text = "Analizando..."
            stopwatch.Reset()
            stopwatch.Start()

            Dim results As String = RunPythonScript(emailContent)

            stopwatch.Stop()
            stTime.Text = $"Análisis completo en {stopwatch.Elapsed.TotalSeconds:0.0} segundos"

            DisplayResults(results)
        Catch ex As Exception
            MessageBox.Show("Error al analizar el correo: " & ex.Message, "Error",
                            MessageBoxButtons.OK, MessageBoxIcon.Error)
        Finally
            Cursor.Current = Cursors.Default
            btnAnalyze.Enabled = True
        End Try
    End Sub

    Private Sub BtnLoadEml_Click(sender As Object, e As EventArgs)
        Using ofd As New OpenFileDialog()
            ofd.Filter = "Archivos EML|*.eml|Todos los archivos|*.*"
            ofd.Title = "Seleccionar archivo EML"
            If ofd.ShowDialog() = DialogResult.OK Then
                Try
                    txtEmail.Text = File.ReadAllText(ofd.FileName)
                Catch ex As Exception
                    MessageBox.Show("Error al cargar el archivo: " & ex.Message, "Error",
                                    MessageBoxButtons.OK, MessageBoxIcon.Error)
                End Try
            End If
        End Using
    End Sub

    Private Sub BtnClear_Click(sender As Object, e As EventArgs)
        txtEmail.Clear()
        lstIndicators.Items.Clear()
        lblVerdict.Text = "VEREDICTO: ESPERANDO ANÁLISIS"
        lblVerdict.ForeColor = Color.Gainsboro
        lblScore.Text = "Puntuación: 0/10"
        lblScore.ForeColor = Color.Silver
        resultPanel.ColorTop = Color.FromArgb(35, 35, 40)
        resultPanel.ColorBottom = Color.FromArgb(75, 30, 30)
        resultPanel.Invalidate()
        stTime.Text = "Tiempo de análisis: 0.0s"
    End Sub

    Private Sub BtnExample_Click(sender As Object, e As EventArgs)
        txtEmail.Text =
            "From: security@micr0soft.com" & Environment.NewLine &
            "To: usuario@example.com" & Environment.NewLine &
            "Subject: URGENTE: Su Cuenta Ha Sido Congelada" & Environment.NewLine & Environment.NewLine &
            "Estimado cliente," & Environment.NewLine & Environment.NewLine &
            "Hemos detectado actividad sospechosa en su cuenta. Para evitar el cierre permanente, debe verificar su información inmediatamente haciendo clic en el siguiente enlace:" & Environment.NewLine & Environment.NewLine &
            "http://bit.ly/seguridad-banco-urgente" & Environment.NewLine & Environment.NewLine &
            "Si no actualiza sus datos en las próximas 24 horas, su cuenta será permanentemente deshabilitada." & Environment.NewLine & Environment.NewLine &
            "Atentamente," & Environment.NewLine &
            "Equipo de Seguridad del Banco" & Environment.NewLine &
            "support@microsft.com"
    End Sub

    '==================== PYTHON ====================
    Private Function RunPythonScript(emailContent As String) As String
        Dim scriptPath As String = FindPythonScript()
        If String.IsNullOrEmpty(scriptPath) Then
            Throw New FileNotFoundException("No se pudo encontrar el archivo detector.py")
        End If

        Try
            Dim psi As New ProcessStartInfo() With {
                .FileName = "python",
                .Arguments = """" & scriptPath & """",
                .RedirectStandardInput = True,
                .RedirectStandardError = True,
                .RedirectStandardOutput = True,
                .UseShellExecute = False,
                .CreateNoWindow = True,
                .StandardErrorEncoding = Encoding.UTF8,
                .StandardOutputEncoding = Encoding.UTF8
            }

            Using process As Process = Process.Start(psi)
                ' Escribir contenido del correo
                Using sw As StreamWriter = process.StandardInput
                    sw.Write(emailContent)
                    sw.Close()
                End Using

                ' Leer resultados
                Dim output As String = process.StandardOutput.ReadToEnd()
                Dim errors As String = process.StandardError.ReadToEnd()

                process.WaitForExit(30000) ' Timeout de 30 segundos

                If process.ExitCode <> 0 Then
                    Throw New Exception("Error en el script de Python (Código " & process.ExitCode & "): " & errors)
                End If

                Return output
            End Using
        Catch ex As Exception
            Throw New Exception("Error ejecutando Python: " & ex.Message, ex)
        End Try
    End Function

    Private Function FindPythonScript() As String
        ' Buscar en el directorio de la aplicación primero
        Dim appDirScript As String = Path.Combine(Application.StartupPath, "detector.py")
        If File.Exists(appDirScript) Then Return appDirScript

        ' Buscar en directorios comunes
        Dim commonPaths As New List(Of String) From {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "detector.py"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "detector.py"),
            "detector.py" ' Directorio actual de trabajo
        }

        For Each path As String In commonPaths
            If File.Exists(path) Then Return path
        Next

        ' Si no se encuentra, preguntar al usuario
        Using ofd As New OpenFileDialog()
            ofd.Filter = "Scripts de Python|*.py|Todos los archivos|*.*"
            ofd.Title = "Seleccione el archivo detector.py"
            If ofd.ShowDialog() = DialogResult.OK Then
                Return ofd.FileName
            End If
        End Using

        Return Nothing
    End Function

    Private Sub CheckPythonStatus()
        If IsPythonInstalled() Then
            stPython.Text = "Python Engine Active"
            stPython.ForeColor = Color.FromArgb(76, 175, 80)
            btnAnalyze.Enabled = True
        Else
            stPython.Text = "Python Engine Not Found"
            stPython.ForeColor = Color.FromArgb(244, 67, 54)
            btnAnalyze.Enabled = False
        End If

        stVB.Text = "VB.NET UI Framework"
    End Sub

    Private Function IsPythonInstalled() As Boolean
        Try
            Dim psi As New ProcessStartInfo("python", "--version") With {
                .RedirectStandardOutput = True,
                .RedirectStandardError = True,
                .UseShellExecute = False,
                .CreateNoWindow = True
            }
            Using p As Process = Process.Start(psi)
                p.WaitForExit(4000)
                Return p.ExitCode = 0
            End Using
        Catch
            Return False
        End Try
    End Function

    '==================== RESULTADOS ====================
    Private Sub DisplayResults(resultsJson As String)
        ' Parseo ligero (sin dependencias) del JSON esperado del script
        Dim status As String = ExtractJsonValue(resultsJson, "status")
        Dim scoreStr As String = ExtractJsonValue(resultsJson, "score")
        Dim score As Integer = 0
        Integer.TryParse(scoreStr, score)

        lblVerdict.Text = "VEREDICTO: " & status.ToUpperInvariant()
        lblScore.Text = $"Puntuación: {score}/10"

        Select Case status
            Case "Malicioso"
                lblVerdict.ForeColor = Color.FromArgb(255, 90, 90)
                lblScore.ForeColor = Color.FromArgb(255, 120, 120)
                resultPanel.ColorTop = Color.FromArgb(60, 10, 10)
                resultPanel.ColorBottom = Color.FromArgb(120, 20, 20)
                PlaySound(SOUND_DANGER)
            Case "Sospechoso"
                lblVerdict.ForeColor = Color.FromArgb(255, 160, 0)
                lblScore.ForeColor = Color.FromArgb(255, 180, 60)
                resultPanel.ColorTop = Color.FromArgb(70, 55, 10)
                resultPanel.ColorBottom = Color.FromArgb(130, 95, 20)
                PlaySound(SOUND_WARNING)
            Case Else
                lblVerdict.ForeColor = Color.FromArgb(90, 200, 110)
                lblScore.ForeColor = Color.FromArgb(120, 220, 140)
                resultPanel.ColorTop = Color.FromArgb(20, 60, 30)
                resultPanel.ColorBottom = Color.FromArgb(40, 100, 55)
                PlaySound(SOUND_SAFE)
        End Select
        resultPanel.Invalidate()

        ' Indicadores
        lstIndicators.BeginUpdate()
        lstIndicators.Items.Clear()
        Dim indicators() As String = ExtractJsonArrayItems(resultsJson, "indicators")
        For Each s In indicators
            If Not String.IsNullOrWhiteSpace(s) Then
                lstIndicators.Items.Add(s.Trim())
            End If
        Next
        lstIndicators.EndUpdate()
    End Sub

    '==================== UTIL JSON LIGERO ====================
    Private Function ExtractJsonValue(json As String, key As String) As String
        ' extrae valores "clave":"valor" o "clave": numero
        Dim m As Match = Regex.Match(json, """" & Regex.Escape(key) & """" & "\s*:\s*(?:""(?<s>[^""]*)""|(?<n>[-\d\.]+)|(?<b>true|false))",
                                     RegexOptions.IgnoreCase Or RegexOptions.Singleline)
        If m.Success Then
            If m.Groups("s").Success Then Return m.Groups("s").Value
            If m.Groups("n").Success Then Return m.Groups("n").Value
            If m.Groups("b").Success Then Return m.Groups("b").Value
        End If
        Return ""
    End Function

    Private Function ExtractJsonArrayItems(json As String, key As String) As String()
        Dim m As Match = Regex.Match(json, """" & Regex.Escape(key) & """" & "\s*:\s*\[(?<arr>.*?)\]",
                                     RegexOptions.Singleline Or RegexOptions.IgnoreCase)
        If Not m.Success Then Return Array.Empty(Of String)()
        Dim arr As String = m.Groups("arr").Value
        ' elementos tipo "texto", quitar comillas y escapar \"
        Dim items As New List(Of String)
        Dim rx As New Regex("\s*""((?:\\""|[^""])*)""\s*", RegexOptions.Singleline)
        For Each mm As Match In rx.Matches(arr)
            Dim item As String = mm.Groups(1).Value.Replace("\""", """")
            items.Add(item)
        Next
        Return items.ToArray()
    End Function

    '==================== SONIDOS ====================
    Private Sub PlaySound(soundFile As String)
        Try
            ' Buscar en varias ubicaciones posibles
            Dim soundPaths As New List(Of String) From {
                Path.Combine(Application.StartupPath, soundFile),
                Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), soundFile),
                Path.Combine(Environment.CurrentDirectory, soundFile)
            }

            Dim soundFound As Boolean = False
            For Each path In soundPaths
                If File.Exists(path) Then
                    soundPlayer.SoundLocation = path
                    soundPlayer.Play()
                    soundFound = True
                    Exit For
                End If
            Next

            ' Si no se encuentra el archivo, usar sonidos del sistema
            If Not soundFound Then
                Select Case soundFile
                    Case SOUND_DANGER
                        SystemSounds.Hand.Play()
                    Case SOUND_WARNING
                        SystemSounds.Exclamation.Play()
                    Case SOUND_SAFE
                        SystemSounds.Asterisk.Play()
                    Case Else
                        SystemSounds.Beep.Play()
                End Select
            End If
        Catch ex As Exception
            ' En caso de error, usar sonidos del sistema
            Try
                SystemSounds.Beep.Play()
            Catch
                ' Ignorar cualquier error final
            End Try
        End Try
    End Sub

    '==================== LIMPIEZA ====================
    Protected Overrides Sub OnFormClosing(e As FormClosingEventArgs)
        MyBase.OnFormClosing(e)
        If soundPlayer IsNot Nothing Then soundPlayer.Dispose()
        If picSkull IsNot Nothing AndAlso picSkull.Image IsNot Nothing Then picSkull.Image.Dispose()
    End Sub

    '==================== PANEL DEGRADADO ====================
    Private NotInheritable Class GradientPanel
        Inherits Panel
        Public Property ColorTop As Color = Color.Black
        Public Property ColorBottom As Color = Color.DimGray
        Protected Overrides Sub OnPaint(e As PaintEventArgs)
            Using br As New Drawing2D.LinearGradientBrush(Me.ClientRectangle, ColorTop, ColorBottom, 90.0F)
                e.Graphics.FillRectangle(br, Me.ClientRectangle)
            End Using
            MyBase.OnPaint(e)
        End Sub
    End Class
End Class