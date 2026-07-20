<#
.SYNOPSIS
    Concatenates .ps1 files in the current directory and splits them into AI digestible chunks.
.DESCRIPTION
    1. Displays the directory tree (tree /f).
    2. Collects all .ps1 files in the current execution folder.
    3. Concatenates their contents with clear file headers.
    4. Splits the combined text into separate .txt files based on a specified chunk size.
#>

# --- Configuration ---
 $ChunkSize = 3500 # Characters per chunk (~800-1000 tokens, safe for most LLMs)
 $OutputFolderName = "AI_Chunks"

# --- 1. Tree /f ---
Write-Host "Current Directory Tree:" -ForegroundColor Cyan
tree /f
Write-Host ""

# --- 2. Collect .ps1 filenames ---
 $CurrentDir = Get-Location
 $Ps1Files = Get-ChildItem -Path $CurrentDir -Filter "*.ps1" -File

if ($Ps1Files.Count -eq 0) {
    Write-Host "No .ps1 files found in the current directory." -ForegroundColor Yellow
    exit
}

Write-Host "Found $($Ps1Files.Count) .ps1 file(s):" -ForegroundColor Cyan
 $Ps1Files | ForEach-Object { Write-Host " - $($_.Name)" }
Write-Host ""

# --- 3. Concatenate string data ---
Write-Host "Reading file contents..." -ForegroundColor Cyan
 $CombinedContent = ""

foreach ($File in $Ps1Files) {
    # Add a clear header for the AI so it knows which file it's reading
    $CombinedContent += "`n`n//============================================================`n"
    $CombinedContent += "// FILE: $($File.Name)`n"
    $CombinedContent += "//============================================================`n`n"
    
    # Append file content
    $CombinedContent += Get-Content $File.FullName -Raw
}

# --- 4. Split into AI digestible chunks ---
Write-Host "Chunking combined data (Chunk size: $ChunkSize characters)..." -ForegroundColor Cyan

 $OutputDir = Join-Path -Path $CurrentDir -ChildPath $OutputFolderName

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

# Clean up old chunks from previous runs
Get-ChildItem -Path $OutputDir -Filter "*.txt" | Remove-Item -Force

 $ChunkIndex = 1
 $Position = 0

while ($Position -lt $CombinedContent.Length) {
    # Determine how many characters to take
    $LengthToTake = [Math]::Min($ChunkSize, $CombinedContent.Length - $Position)
    $Chunk = $CombinedContent.Substring($Position, $LengthToTake)

    # Smart splitting: If the chunk isn't the very end of the text, 
    # look for the last newline character to avoid slicing a line of code in half.
    if ($Position + $LengthToTake -lt $CombinedContent.Length) {
        $LastNewLine = $Chunk.LastIndexOf("`n")
        
        # Only adjust if a newline was found and it's not right at the beginning (0)
        if ($LastNewLine -gt 0) {
            $Chunk = $Chunk.Substring(0, $LastNewLine + 1)
            $Position += $LastNewLine + 1
        } else {
            # No newline found, just take the full chunk size
            $Position += $LengthToTake
        }
    } else {
        # We've reached the end of the text
        $Position += $LengthToTake
    }

    # Save chunk to file
    $ChunkFileName = "chunk_$ChunkIndex.txt"
    $ChunkFilePath = Join-Path -Path $OutputDir -ChildPath $ChunkFileName
    
    $Chunk | Out-File -FilePath $ChunkFilePath -Encoding UTF8
    Write-Host "  Created $ChunkFileName (Length: $($Chunk.Length) chars)" -ForegroundColor Green
    
    $ChunkIndex++
}

Write-Host "`nDone! Chunks saved to: $OutputDir" -ForegroundColor Cyan