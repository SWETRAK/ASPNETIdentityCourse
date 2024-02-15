using ASPNETIdentityCourse;
using ASPNETIdentityCourse.Mappings;
using ASPNETIdentityCourse.Models.Entities;
// using ASPNETIdentityCourse.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Unleash;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<ApplicationDbContext>(opt =>
{
    opt.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection"));
});

builder.Services.AddAutoMapper(cfg =>
{
    cfg.AddProfile<AccountMappingProfile>();
});

builder.Services.ConfigureApplicationCookie(opt =>
{
    opt.AccessDeniedPath = new PathString("/Account/NoAccess");
});

// Password can be configured 
builder.Services.Configure<IdentityOptions>(opt =>
{
    opt.Password.RequireNonAlphanumeric = false;
    opt.Lockout.MaxFailedAccessAttempts = 3;
    opt.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromDays(10); // Can be replaced with as long as we can
    opt.SignIn.RequireConfirmedEmail = false;
});

// Can be IdentityUser instead ApplicationUser
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders(); // Needed for resetting password working  
// builder.Services.AddScoped<IEmailSender, EmailSenderService>();

// Configuration of unleash, feature flag management service connection
builder.Services.AddSingleton<IUnleash>(s =>
{
    var unleashSettings = new UnleashSettings
    {
        AppName = "test-dotnet-app",
        UnleashApi = new Uri("http://localhost:4242/api/"),
        FetchTogglesInterval = TimeSpan.FromSeconds(10),
        CustomHttpHeaders = new Dictionary<string, string>()
        {
            {"Authorization","default:development.aea907266d4b9efe9846b38a825f3fa64d85b8a74755b0f78acc90f1"}
        }
    };
    return new DefaultUnleash(unleashSettings);
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication(); // Always before Authorization
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();