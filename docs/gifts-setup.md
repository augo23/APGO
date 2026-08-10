# Gifts setup

The code side is done in three places: the apps' Support screens (IAP tiers +
monthly subscriptions + website link) and the website's `/support.html`. This
walkthrough covers the account-side setup that only you can do. Do them in
order — the Stripe links feed both the website and the apps' "any amount"
button.

APGO is a personal project, not a charity: everywhere below, gifts are
"gifts to the developer", never "charitable donations" (never use that phrase). Both app stores and
Stripe care about that wording.

## 1. Stripe (website: any amount, Apple Pay + Google Pay)

1. Create an account at <https://dashboard.stripe.com/register> (sole
   proprietor / individual is fine; you'll enter your bank account for
   payouts).
2. Dashboard → **Payment Links** → **+ New**:
   - **One-time link**: choose "Customers choose what to pay". Name it
     "APGO — one-time gift". Set a sensible minimum (e.g. $1) so card fees
     don't eat micro-gifts.
   - **Monthly link**: create a product "APGO monthly support", recurring
     monthly, "Customers choose what to pay".
3. Copy the two `https://donate.stripe.com/…` URLs into
   `apgo-website/site/support.html`, replacing the two `REPLACE_*` hrefs.
   (The buttons stay hidden until you do, so deploying early is safe.)
4. Apple Pay and Google Pay appear automatically on Stripe's checkout page —
   no domain verification needed because checkout runs on stripe.com, not
   your domain.
5. Fees: 2.9% + 30¢ per card/wallet charge. Nothing else.

## 2. Website domain in the apps

Both apps link to the gift page for custom amounts. Replace the
placeholder with the real public site URL:

- `ios/App/SupportView.swift` → `SupportConstants.giftURL`
- `android/app/src/main/java/org/apgo/app/Billing.kt` → `Support.giftUrl`

## 3. App Store Connect (iOS)

Products live under your app → **Monetization → In-App Purchases** /
**Subscriptions**. IDs must match `SupportConstants` exactly.

Consumables ($1 / $3 / $5 / $10 / $25 / $50 / $100):

    org.apgo.gift.1  org.apgo.gift.3  org.apgo.gift.5  org.apgo.gift.10
    org.apgo.gift.25 org.apgo.gift.50 org.apgo.gift.100

Auto-renewable subscriptions — create one subscription group "APGO Support",
then four monthly products ($1 / $3 / $5 / $10):

    org.apgo.monthly.1  org.apgo.monthly.3  org.apgo.monthly.5  org.apgo.monthly.10

Notes:
- Each product needs a display name, description, and review screenshot
  before it can go live; they're reviewed with your next app version.
- Subscriptions additionally require the App Privacy + paid-apps agreement
  to be signed (Agreements, Tax, and Banking).
- The "tip jar" model (gifts to the developer through IAP) is explicitly
  allowed. The website link for custom amounts is the part Apple has
  historically been inconsistent about: gifts aren't "digital content"
  so guideline 3.1.1 shouldn't apply, but if review flags it, resubmit with
  the link section removed on iOS only — the constant is isolated so it's a
  two-line change.

## 4. Play Console (Android)

Products live under your app → **Monetize → Products**. IDs must match
`Support` in `Billing.kt` exactly.

In-app products, all **consumable-style** (the app consumes them so they're
repeatable), $1 / $3 / $5 / $10 / $25 / $50 / $100:

    apgo_gift_1  apgo_gift_3  apgo_gift_5  apgo_gift_10
    apgo_gift_25 apgo_gift_50 apgo_gift_100

Subscriptions — four products, one monthly auto-renewing base plan each,
$1 / $3 / $5 / $10:

    apgo_monthly_1  apgo_monthly_3  apgo_monthly_5  apgo_monthly_10

Notes:
- The code acknowledges subscription purchases automatically (unacknowledged
  subs are refunded by Play after 3 days) and consumes one-time gifts.
- A merchant account (Payments profile) must be linked before products can
  be created.
- Play is more relaxed about external donation links than Apple; the website
  button is fine.

## 5. GitHub Sponsors (optional, zero fees)

<https://github.com/sponsors> → enable for the `augo23` account (payouts via
Stripe Connect). Individual sponsorships carry **zero fees** — GitHub covers
processing — so it's the highest-yield channel; the gift page already
links to it. If you skip this, remove that card from `support.html`.

## Money handling notes (not legal advice)

Gifts to you are generally taxable income to report (hobby/self-employment
income — a tax professional can say which bucket); "not tax-deductible for
the giver" is already stated in every UI. Stripe/Play/Apple each produce
annual summaries (1099-K etc. depending on volume) — keep the three payout
streams pointed at one bank account to simplify bookkeeping.
