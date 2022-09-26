@{
   RootModule         = 'winFileExtProgId'
   ModuleVersion      = '0.1'

   RequiredModules    = @(
      'console'
   )

   RequiredAssemblies = @(
   )

   FunctionsToExport  = @(
      'show-winFileExtAssociation',
       'set-winFileExtAssociation'
   )

   ScriptsToProcess   = @(
   )

   AliasesToExport    = @(
   )
}
