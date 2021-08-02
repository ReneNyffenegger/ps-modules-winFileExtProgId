@{
   RootModule         = 'winFileExtProgId'
   ModuleVersion      = '0.1'

   RequiredModules    = @(
      'console'
   )

   RequiredAssemblies = @(
   )

   FunctionsToExport  = @(
      'show-winFileEXtAssociation',
       'set-winFileExtAssociation'
   )

   ScriptsToProcess   = @(
   )

   AliasesToExport    = @(
   )
}
