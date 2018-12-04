## ASP.NET Core Identity library for ArangoDB

### Install

PM> Install-Package BorderEast.ASPNetCore.Identity.ArangoDB

### Setting up Guide
See the SampleWebAppliction project for a working example, or follow these steps.

#### 1 Create a new ASP.NET Core web application and choose Individual User Accounts for the Authentication method.

#### 2 Add reference to DotNetCore ArangoDB Driver & Identity

- PM> Install-Package Microsoft.AspNetCore.Identity or search NuGet Gallery for Microsoft.AspNetCore.Identity.
- PM> Install-Package BorderEast.ArangoDB.Client or search NuGet Gallery for BorderEast.ArangoDB.Client.
- PM> Install-Package BorderEast.ASPNetCore.Identity.ArangoDB

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
- Change reference on base class `IdentityUser` on `Models.ApplicationUser` from the removed EF using statement to `BorderEast.ASPNetCore.Identity.ArangoDB;` and add this annotation `[JsonObject(Id = "IdentityUser")]` 
- Remove the following code in `Startup.cs`

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

            services.AddIdentity<ApplicationUser, IdentityRole>()
            .AddArangoDbStores()
            .AddDefaultTokenProviders();
            
Ensure this is all added before the `services.AddMvc();` statement.

#### 6 Setup ArangoDB
Ensure ArangoDB is installed and adjust the database/username/password settings above. To run as is, set the root password to your machine username (run `echo %USERNAME%` on cmd line) and create the IdentityUser and IdentityRole collections in the your database using the following script:

			db._create("IdentityUser");
			db._create("IdentityRole");

			db.IdentityUser.ensureIndex({ type: "hash", fields: [ "normalizedUserName" ], unique: true });
			db.IdentityUser.ensureIndex({ type: "hash", fields: [ "normalizedEmail" ], unique: true });
			db.IdentityUser.ensureIndex({ type: "hash", fields: [ "logins[*].providerKey" ] });
