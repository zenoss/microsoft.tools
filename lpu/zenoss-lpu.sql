/*
Copyright 2014 Zenoss Inc., All rights reserved

DISCLAIMER: USE THE SOFTWARE AT YOUR OWN RISK
This script modifies the registry and several system access permissions. Use with caution!

You must set the LPUuser variable before script will execute.

example:

SET @LPUuser = 'ZENLABS\Zenny'   <---- Domain user account
SET @LPUuser = 'SQL1\Benny'     <---- Local Windows account
SET @LPUuser = 'kenny'          <---- SQL Server Account

** NOTE: This script will not create users. It will only add existing users to the 
required access areas. If you are using a local SQL account you must create that first.

*/

DECLARE @LPUuser VARCHAR(50)
SET @LPUuser = 'DOMAIN\USER'

BEGIN TRY
    IF NOT EXISTS
        (SELECT loginname
        FROM master.dbo.syslogins
        WHERE name=@LPUuser)
    BEGIN
        IF (@LPUuser like '%\%')
            EXEC('CREATE LOGIN "'+@LPUuser+'" FROM WINDOWS;')
        USE master;
        EXEC('GRANT VIEW SERVER STATE TO ['+@LPUuser+']')
        PRINT
            'The Zenoss user has successfully been created and granted necessary permissions.';
    END
    ELSE
    BEGIN
        USE master;
        EXEC('GRANT VIEW SERVER STATE TO ['+@LPUuser+']')
        PRINT
            'The Zenoss user was already created so necessary permissions were granted.'
    END
END TRY
BEGIN CATCH
    SELECT
        ERROR_NUMBER() AS ErrorNumber,
        ERROR_MESSAGE() AS ErrorMessage;
    PRINT
        'ERROR Setting Zenoss User: '+ERROR_MESSAGE();
END CATCH;
GO