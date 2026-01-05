/**
 * Visual testing for Guardian dashboard using ai-browser-test
 * 
 * Tests the dashboard UI for accessibility, design quality, and functionality.
 */

import { test, expect } from '@playwright/test';
import { validateScreenshot } from 'ai-browser-test';

const DASHBOARD_URL = process.env.DASHBOARD_URL || 'http://localhost:8080';
const DASHBOARD_API_KEY = process.env.DASHBOARD_API_KEY || '';

test.describe('Guardian Dashboard Visual Tests', () => {
  
  test.beforeAll(async () => {
    // Ensure dashboard is running
    console.log(`Testing dashboard at: ${DASHBOARD_URL}`);
  });

  test('dashboard homepage visual validation', async ({ page }) => {
    // Navigate to dashboard
    await page.goto(DASHBOARD_URL);
    await page.waitForLoadState('networkidle');
    
    // Wait for dashboard to load
    await page.waitForSelector('body', { timeout: 10000 });
    
    // Capture screenshot
    const screenshotPath = `test-results/dashboard-homepage-${Date.now()}.png`;
    await page.screenshot({ path: screenshotPath, fullPage: true });
    
    // Validate with VLLM
    const result = await validateScreenshot(
      screenshotPath,
      `Evaluate the Guardian monitoring dashboard homepage:

REQUIREMENTS:
- Is the dashboard clearly displaying monitoring data?
- Are cost metrics visible and properly formatted?
- Are service status indicators (✓/✗) clearly shown?
- Is the layout clean and organized?

ACCESSIBILITY:
- Is text contrast ≥4.5:1 (WCAG AA minimum)?
- Are interactive elements clearly identifiable?
- Is the color scheme accessible (not relying solely on color)?

DESIGN QUALITY:
- Is the information hierarchy clear?
- Are tables/charts readable?
- Is there appropriate spacing between elements?
- Are error states clearly indicated?

FUNCTIONALITY:
- Are all monitoring services listed?
- Is the refresh functionality visible?
- Are cost totals displayed prominently?`,
      {
        testType: 'dashboard-homepage',
        viewport: { width: 1280, height: 720 }
      }
    );
    
    // Assertions
    expect(result.enabled).toBe(true);
    if (result.score !== null) {
      expect(result.score).toBeGreaterThanOrEqual(7);
    }
    expect(result.issues).toBeInstanceOf(Array);
    
    console.log(`Dashboard score: ${result.score}/10`);
    console.log(`Issues found: ${result.issues.length}`);
    if (result.issues.length > 0) {
      console.log('Issues:', result.issues);
    }
  });

  test('dashboard with API key authentication', async ({ page }) => {
    if (!DASHBOARD_API_KEY) {
      test.skip('DASHBOARD_API_KEY not set, skipping authentication test');
    }
    
    // Navigate to dashboard with API key
    await page.setExtraHTTPHeaders({
      'X-API-Key': DASHBOARD_API_KEY
    });
    
    await page.goto(`${DASHBOARD_URL}/api/report`);
    await page.waitForLoadState('networkidle');
    
    // Check if we get JSON response
    const content = await page.content();
    expect(content).toContain('"checks"');
    expect(content).toContain('"summary"');
    
    console.log('✓ API authentication working');
  });

  test('dashboard error states visual validation', async ({ page }) => {
    // Navigate to dashboard
    await page.goto(DASHBOARD_URL);
    await page.waitForLoadState('networkidle');
    
    // Wait for any error indicators
    await page.waitForTimeout(2000);
    
    // Capture screenshot
    const screenshotPath = `test-results/dashboard-errors-${Date.now()}.png`;
    await page.screenshot({ path: screenshotPath, fullPage: true });
    
    // Validate error display
    const result = await validateScreenshot(
      screenshotPath,
      `Evaluate how the dashboard displays errors:

ERROR DISPLAY:
- Are errors clearly visible and distinguishable from success states?
- Is error text readable and informative?
- Are error states using appropriate visual indicators (red, warning icons)?
- Is there clear separation between different error types?

ACCESSIBILITY:
- Do errors have sufficient contrast?
- Are errors accessible to screen readers?
- Is error information not conveyed by color alone?

DESIGN:
- Are errors not overwhelming the interface?
- Is there a clear way to dismiss or handle errors?
- Are error messages actionable?`,
      {
        testType: 'dashboard-errors',
        viewport: { width: 1280, height: 720 }
      }
    );
    
    if (result.score !== null) {
      expect(result.score).toBeGreaterThanOrEqual(6);
    }
    
    console.log(`Error display score: ${result.score}/10`);
  });

  test('dashboard cost metrics display', async ({ page }) => {
    await page.goto(DASHBOARD_URL);
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    // Capture screenshot
    const screenshotPath = `test-results/dashboard-costs-${Date.now()}.png`;
    await page.screenshot({ path: screenshotPath, fullPage: true });
    
    // Validate cost display
    const result = await validateScreenshot(
      screenshotPath,
      `Evaluate the cost metrics display:

COST DISPLAY:
- Are cost metrics clearly visible?
- Is the total cost prominently displayed?
- Are individual service costs listed?
- Are costs formatted as currency (e.g., $X.XX)?

CLARITY:
- Are cost values easy to read?
- Is there clear labeling (e.g., "Total Cost", "Service Costs")?
- Are cost metrics grouped logically?

DESIGN:
- Is the cost information visually distinct?
- Are there appropriate units and formatting?
- Is the cost display not cluttered?`,
      {
        testType: 'dashboard-costs',
        viewport: { width: 1280, height: 720 }
      }
    );
    
    if (result.score !== null) {
      expect(result.score).toBeGreaterThanOrEqual(7);
    }
    
    console.log(`Cost display score: ${result.score}/10`);
    if (result.issues.length > 0) {
      console.log('Cost display issues:', result.issues);
    }
  });
});

