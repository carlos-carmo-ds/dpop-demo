# syntax=docker/dockerfile:1

# Build roda na arquitetura da máquina de build e compila para a arquitetura alvo
# (-a $TARGETARCH), então o multi-arch não precisa de emulação (QEMU).
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG TARGETARCH
WORKDIR /src

COPY DpopDemo.Api.csproj ./
RUN dotnet restore -a $TARGETARCH

COPY . .
RUN dotnet publish -c Release -a $TARGETARCH --no-restore -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app ./

# "Urls" no appsettings.json é localhost:5080 (dev local). No container, escuta em todas as
# interfaces na 8080. Variável de ambiente tem precedência sobre o appsettings.
ENV Urls=http://+:8080
EXPOSE 8080

# A imagem aspnet já traz o usuário não-root "app".
USER $APP_UID
ENTRYPOINT ["dotnet", "DpopDemo.Api.dll"]
