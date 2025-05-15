dotnet publish -c Release -r win-x64 --self-contained true \
  /p:PublishSingleFile=false \
  /p:ReadyToRun=true \
  /p:TieredCompilationQuickJit=true
