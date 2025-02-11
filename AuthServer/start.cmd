@echo off
rem https://learn.microsoft.com/en-us/aspnet/core/security/docker-https?view=aspnetcore-6.0
rem remove the cert if we not going to host over https but pass to alb to provide cert.
rem create a self signed cert
rem dotnet dev-certs https -ep %USERPROFILE%\.aspnet\https\aspnetapp.pfx -p password
rem dotnet dev-certs https --trust
docker build -t hh_dev_ciam_test .
docker rm -f hh_dev_ciam_test_img
docker run --name hh_dev_ciam_test_img --rm -it -p 8000:80 -p 8001:443 -e ASPNETCORE_URLS="https://+:443;http://+:80" -e ASPNETCORE_HTTPS_PORTS=8001 -e ASPNETCORE_ENVIRONMENT="Production" -e ASPNETCORE_Kestrel__Certificates__Default__Password="password" -e ASPNETCORE_Kestrel__Certificates__Default__Path=/https/aspnetapp.pfx -v %USERPROFILE%\.aspnet\https:/https/ hh_dev_ciam_test

pause