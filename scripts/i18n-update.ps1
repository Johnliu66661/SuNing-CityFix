param(
  [switch]$Init
)
$ErrorActionPreference = 'Stop'
if ($Init) {
  pybabel extract -F babel.cfg -o messages.pot .
  pybabel init -i messages.pot -d translations -l zh
  pybabel init -i messages.pot -d translations -l en
} else {
  pybabel extract -F babel.cfg -o messages.pot .
  pybabel update -i messages.pot -d translations
}
pybabel compile -d translations
Write-Host "i18n done." -ForegroundColor Green
