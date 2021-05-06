<!-- markdownlint-disable MD002 MD041 -->

## Configure Your Application to Use Auth0

[Universal Login](/hosted-pages/login) is the easiest way to set up authentication in your application. We recommend using it for the best experience, best security and the fullest array of features. This guide will use it to provide a way for your users to log in to your ASP.NET Core application.

### Install dependencies

To integrate Auth0 with ASP.NET Core you will use the Cookie and OpenID Connect (OIDC) authentication handlers.

If you are adding this to your own existing project, then please make sure that you add the `Auth0.AspNetCore.Mvc` package to your application.

```bash
Install-Package Auth0.AspNetCore.Mvc -IncludePrerelease
```

### Install and configure the SDK

To enable authentication in your ASP.NET Core application, use the middleware provided by our SDK.
Go to the `ConfigureServices` method of your `Startup` class and call `services.AddAuth0Mvc()` to configure the Auth0 ASP.NET Core SDK.

Configure other parameters, such as `Domain`, `ClientId` and `ClientSecret`.

By default, the OIDC middleware requests both the `openid` and `profile` scopes. Because of that, you may get a large ID Token in return. We suggest that you ask only for the scopes you need. You can read more about requesting additional scopes in the [User Profile step](/quickstart/webapp/aspnet-core/02-user-profile).

::: note
In the code sample below, only the `openid` scope is requested.
:::

```cs
// Startup.cs

public void ConfigureServices(IServiceCollection services)
{
    // Cookie configuration for HTTP to support cookies with SameSite=None
    services.ConfigureSameSiteNoneCookies();

    // Cookie configuration for HTTPS
    // services.Configure<CookiePolicyOptions>(options =>
    // {
    //    options.MinimumSameSitePolicy = SameSiteMode.None
    // });

    // Add authentication services
    services
        .AddAuth0Mvc(options => {
            // Set the authority to your Auth0 domain
            options.Domain = Configuration["Auth0:Domain"];
            // Configure the Auth0 Client ID and Client Secret
            options.ClientId = Configuration["Auth0:ClientId"];
            options.ClientSecret = Configuration["Auth0:ClientSecret"];
        });

    // Add framework services.
    services.AddControllersWithViews();
}
```

::: note
The `ConfigureSameSiteNoneCookies` method used above was added as part of the [sample application](https://github.com/auth0-samples/auth0-aspnetcore-mvc-samples/blob/master/Quickstart/01-Login/Support/SameSiteServiceCollectionExtensions.cs) in order to ([make cookies with SameSite=None work over HTTP when using Chrome](https://blog.chromium.org/2019/10/developers-get-ready-for-new.html)). We recommend using HTTPS instead of HTTP, which removes the need for the `ConfigureSameSiteNoneCookies` method.
:::

Next, add the authentication middleware. In the `Configure` method of the `Startup` class, call the `UseAuthentication` and `UseAuthorization` methods.

```csharp
// Startup.cs

public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
    if (env.IsDevelopment())
    {
        app.UseDeveloperExceptionPage();
    }
    else
    {
        app.UseExceptionHandler("/Home/Error");
        // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
        app.UseHsts();
    }
    app.UseStaticFiles();
    app.UseCookiePolicy();

    app.UseRouting();

    app.UseAuthentication();
    app.UseAuthorization();

    app.UseEndpoints(endpoints =>
    {
        endpoints.MapControllerRoute(
            name: "default",
            pattern: "{controller=Home}/{action=Index}/{id?}");
    });
}
```

## Trigger Authentication

### Add the Login and Logout methods

Add the `Login` and `Logout` actions to `AccountController`.

To add the `Login` action, call `ChallengeAsync` and pass "Auth0" (`Constants.AuthenticationScheme`) as the authentication scheme. This will invoke the OIDC authentication handler that our SDK registers internally.

After the OIDC middleware signs the user in, the user is also automatically signed in to the cookie middleware. This allows the user to be authenticated on subsequent requests.

For the `Logout` action, you need to sign the user out of both the Auth0 middleware as well as the cookie middleware.

The `RedirectUri` passed in both instances indicates where the user is redirected after they log in or fail to log in.

```cs
// Controllers/AccountController.cs

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Auth0.AspNetCore.Mvc;

public class AccountController : Controller
{
    public async Task Login(string returnUrl = "/")
    {
        await HttpContext.ChallengeAsync(Constants.AuthenticationScheme, new AuthenticationProperties() { RedirectUri = returnUrl });
    }

    [Authorize]
    public async Task Logout()
    {
        await HttpContext.SignOutAsync(Constants.AuthenticationScheme, new AuthenticationProperties
        {
            // Indicate here where Auth0 should redirect the user after a logout.
            // Note that the resulting absolute Uri must be added to the
            // **Allowed Logout URLs** settings for the app.
            RedirectUri = Url.Action("Index", "Home")
        });
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }
}
```

### Add the Login and Logout buttons

Add the **Log In** and **Log Out** buttons to the navigation bar. In the `/Views/Shared/_Layout.cshtml` file, in the navigation bar section, add code that displays the **Log Out** button when the user is authenticated and the **Log In** button if not. The buttons link to the `Logout` and `Login` actions in the `AccountController`:

```html
<!-- Views/Shared/_Layout.cshtml -->
<div class="navbar-collapse collapse d-sm-inline-flex flex-sm-row-reverse">
    <ul class="nav navbar-nav">
        <li><a asp-area="" asp-controller="Home" asp-action="Index">Home</a></li>
    </ul>
    <ul class="nav navbar-nav navbar-right">
        @if (User.Identity.IsAuthenticated)
        {
            <li><a id="qsLogoutBtn" asp-controller="Account" asp-action="Logout">Logout</a></li>
        }
        else
        {
            <li><a id="qsLoginBtn" asp-controller="Account" asp-action="Login">Login</a></li>
        }
    </ul>
</div>
```

### Run the application

When the user selects the **Log In** button, the OIDC middleware redirects them to the hosted version of the [Lock](/libraries/lock/v10/customization) widget in your Auth0 domain.

#### About the login flow

1. The user clicks on the **Log In** button and is directed to the `Login` route.
2. The `ChallengeAsync` tells the ASP.NET authentication middleware to issue a challenge to the authentication handler registered with the Auth0 `authenticationScheme` parameter. The parameter uses the `Constants.AuthenticationScheme` value, which is configured as "Auth0" internally in our SDK.
3. The SDK redirects the user to the Auth0 `/authorize` endpoint, which enabled the user to log in with their username and password, social provider or any other identity provider.
4. Once the user has logged in, Auth0 calls back to the `/callback` endpoint in your application and passes along an authorization code.
5. The SDK intercepts requests made to the `/callback` path.
6. The handler looks for the authorization code, which Auth0 sent in the query string.
7. The SDK calls the `/oauth/token` endpoint to exchange the authorization code for the user's ID and Access Tokens.
8. The SDK extracts the user information from the claims on the ID Token.
9. The SDK returns a successful authentication response and a cookie which indicates that the user is authenticated. The cookie contains claims with the user's information. The cookie is stored, so that the cookie middleware will automatically authenticate the user on any future requests. The SDK receives no more requests, unless it is explicitly challenged.

## Obtain an Access Token for Calling an API

If you want to call an API from your MVC application, you need to obtain an Access Token issued for the API you want to call. To obtain the token, pass an additional `audience` parameter containing the API Identifier to the Auth0 authorization endpoint. You can get the API Identifier from the [API Settings](${manage_url}/#/apis) for the API you want to use.

In the configuration for the `Auth0Options` object, set the `Audience` parameter.

```csharp
// Startup.cs

public void ConfigureServices(IServiceCollection services)
{
    services
        .AddAuth0Mvc(options => {
            options.Audience = Configuration["Auth0:Audience"];
        });
}
```

Be sure to also update your application's `appsettings.json` file to include the Audience configuration:

``` xml
"Auth0": {
    ...
    "Audience": "${apiIdentifier}"
}
```

### Store and retrieve the tokens

The SDK automatically decodes the ID Token returned from Auth0 and adds the claims from the ID Token as claims in the `ClaimsIdentity`. This means that you can use `User.Claims.FirstOrDefault("<claim type>").Value` to obtain the value of any claim inside any action in your controllers.

The seed project contains a controller action and view that display the claims associated with a user. Once a user has logged in, you can go to `/Account/Claims` to see these claims.

The SDK also stores the Access Token in the HttpContext, allowing you to retrieve the token by using the `HttpContext.GetTokenAsync()` method.

```csharp
// Inside one of your controller actions

if (User.Identity.IsAuthenticated)
{
    string accessToken = await HttpContext.GetTokenAsync("access_token");
    
    // if you need to check the Access Token expiration time, use this value
    // provided on the authorization response and stored.
    // do not attempt to inspect/decode the access token
    DateTime accessTokenExpiresAt = DateTime.Parse(
        await HttpContext.GetTokenAsync("expires_at"), 
        CultureInfo.InvariantCulture,
        DateTimeStyles.RoundtripKind);
        
    string idToken = await HttpContext.GetTokenAsync("id_token");

    // Now you can use them. For more info on when and how to use the
    // Access Token and ID Token, see https://auth0.com/docs/tokens
}
```

For general information on using APIs with web applications, see the [Authorization Code Flow](/flows/concepts/auth-code) article.
