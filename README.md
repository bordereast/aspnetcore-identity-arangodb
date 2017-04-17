## ASP.NET Core Identity library for ArangoDB


### Setting up
See the SampleWebAppliction project for a working example, or follow these steps.

#### 1 Create a new ASP.NET Core web application and choose Individual User Accounts for the Authentication method.

#### 2 Add reference to DotNetCore ArangoDB Driver & Identity

PM> Install-Package BorderEast.ArangoDB.Client or search NuGet Gallery for BorderEast.ArangoDB.Client.
PM> Install-Package Microsoft.AspNetCore.Identity or search NuGet Gallery for Microsoft.AspNetCore.Identity.

Reference BorderEast.ASPNETCore.Identity.ArangoDB (this repository) via NuGet.

Rebuild and ensure BorderEast namespace is available (In VS2017 I had to close and reopen solution. Bug?).

#### 3 Remove dependencies to Entity Framework

- Microsoft.AspNetCore.Diagnostics.EntityFrameworkCore
- Microsoft.AspNetCore.Identity.EntityFrameworkCore
- Microsoft.EntityFrameworkCore.Design
- Microsoft.EntityFrameworkCore.SqlServer
- Microsoft.EntityFrameworkCore.SqlServer.Design
- Microsoft.EntityFrameworkCore.Tools

#### 4 Remove EF Related Items

- Delete Data folder containing migrations and `ApplicationDbContext.cs`
- Remove all `using` statements refering to Entity Framework
- Change reference on base class `IdentityUser` on `Models.ApplicationUser` from the removed EF using statement to `BorderEast.ASPNetCore.Identity.ArangoDB;`
- Comment out the following code in `Startup.cs`

    `services.AddDbContext<ApplicationDbContext>(options =>
        options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));`

    `services.AddIdentity<ApplicationUser, IdentityRole>()
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders();`
        
    `app.UseDatabaseErrorPage();`
    
Proejct should now compile

#### 5 Add ArangoDB Identity

In `Startup.cs`, add the following to `ConfigureServices`:

            ArangoClient.Client().SetDefaultDatabase(new BorderEast.ArangoDB.Client.Database.ClientSettings()
            {
                DatabaseName = "_system",
                Protocol = BorderEast.ArangoDB.Client.Database.ProtocolType.HTTP,
                ServerAddress = "localhost",
                ServerPort = 8529,
                SystemCredential = new System.Net.NetworkCredential("root", Environment.GetEnvironmentVariable("USERNAME")),
                DatabaseCredential = new System.Net.NetworkCredential("root", Environment.GetEnvironmentVariable("USERNAME")),
                AutoCreate = true,
                HTTPClient = new System.Net.Http.HttpClient(),
                IsDebug = true
            });

            services.AddSingleton<IArangoClient>(ArangoClient.Client());

            services.AddIdentity<ApplicationUser, IdentityRole>(options => {
                options.Cookies.ApplicationCookie.AuthenticationScheme = "ApplicationCookie";
                options.Cookies.ApplicationCookie.CookieName = "Interop";
            })
            .AddArangoDbStores()
            .AddDefaultTokenProviders();
            
Ensure this is all added before the `services.AddMvc();` statement.
