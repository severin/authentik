"""captcha tests"""

from http import HTTPStatus

from django.urls import reverse
from requests_mock import Mocker

from authentik.core.tests.utils import create_test_admin_user, create_test_flow
from authentik.events.logs import capture_logs
from authentik.flows.markers import StageMarker
from authentik.flows.models import FlowDesignation, FlowStageBinding
from authentik.flows.planner import FlowPlan
from authentik.flows.tests import APIFlowTestCase
from authentik.flows.views.executor import SESSION_KEY_PLAN
from authentik.lib.generators import generate_id
from authentik.stages.captcha.models import CaptchaRequestContentType, CaptchaStage
from authentik.stages.captcha.stage import (
    PLAN_CONTEXT_CAPTCHA_PRIVATE_KEY,
    PLAN_CONTEXT_CAPTCHA_SITE_KEY,
)

# https://developers.google.com/recaptcha/docs/faq#id-like-to-run-automated-tests-with-recaptcha.-what-should-i-do
RECAPTCHA_PUBLIC_KEY = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"
RECAPTCHA_PRIVATE_KEY = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"


class TestCaptchaStage(APIFlowTestCase):
    """Captcha tests"""

    def setUp(self):
        super().setUp()
        self.user = create_test_admin_user()
        self.flow = create_test_flow(FlowDesignation.AUTHENTICATION)

        self.stage: CaptchaStage = CaptchaStage.objects.create(
            name="captcha",
            public_key=RECAPTCHA_PUBLIC_KEY,
            private_key=RECAPTCHA_PRIVATE_KEY,
        )
        self.binding = FlowStageBinding.objects.create(target=self.flow, stage=self.stage, order=2)

    @Mocker()
    def test_valid(self, mock: Mocker):
        """Test valid captcha"""
        mock.post(
            "https://www.recaptcha.net/recaptcha/api/siteverify",
            json={
                "success": True,
                "score": 0.5,
            },
        )
        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()
        response = self.client.post(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
            {"token": "PASSED"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertStageRedirects(response, reverse("authentik_core:root-redirect"))
        self.assertEqual(
            mock.request_history[0].headers["Content-Type"],
            CaptchaRequestContentType.FORM,
        )
        self.assertIn("response=PASSED", mock.request_history[0].text)

    @Mocker()
    def test_valid_json_content_type(self, mock: Mocker):
        """Test valid captcha with JSON verification request"""
        self.stage.request_content_type = CaptchaRequestContentType.JSON
        self.stage.save()
        mock.post(
            "https://www.recaptcha.net/recaptcha/api/siteverify",
            json={
                "success": True,
                "score": 0.5,
            },
        )
        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()
        response = self.client.post(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
            {"token": "PASSED"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertStageRedirects(response, reverse("authentik_core:root-redirect"))
        self.assertEqual(
            mock.request_history[0].headers["Content-Type"],
            CaptchaRequestContentType.JSON,
        )
        self.assertEqual(mock.request_history[0].json()["response"], "PASSED")

    @Mocker()
    def test_valid_override(self, mock: Mocker):
        """Test valid captcha"""
        self.stage.private_key = generate_id()
        self.stage.public_key = generate_id()
        mock.post(
            "https://www.recaptcha.net/recaptcha/api/siteverify",
            json={
                "success": True,
                "score": 0.5,
            },
        )
        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        site_key = generate_id()
        private_key = generate_id()
        plan.context = {
            PLAN_CONTEXT_CAPTCHA_SITE_KEY: site_key,
            PLAN_CONTEXT_CAPTCHA_PRIVATE_KEY: private_key,
        }
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()
        response = self.client.get(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
        )
        self.assertStageResponse(response, component="ak-stage-captcha", site_key=site_key)
        response = self.client.post(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
            {"token": "PASSED"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertStageRedirects(response, reverse("authentik_core:root-redirect"))
        self.assertIn(private_key, mock.request_history[0].text)

    @Mocker()
    def test_invalid_score_high(self, mock: Mocker):
        """Test invalid captcha (score too high)"""
        mock.post(
            "https://www.recaptcha.net/recaptcha/api/siteverify",
            json={
                "success": True,
                "score": 99,
            },
        )
        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()
        response = self.client.post(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
            {"token": "PASSED"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertStageResponse(
            response,
            component="ak-stage-captcha",
            response_errors={"token": [{"string": "Invalid captcha response", "code": "invalid"}]},
        )

    @Mocker()
    def test_invalid_score_low(self, mock: Mocker):
        """Test invalid captcha (score too low)"""
        mock.post(
            "https://www.recaptcha.net/recaptcha/api/siteverify",
            json={
                "success": True,
                "score": -3,
            },
        )
        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()
        response = self.client.post(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
            {"token": "PASSED"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertStageResponse(
            response,
            component="ak-stage-captcha",
            response_errors={"token": [{"string": "Invalid captcha response", "code": "invalid"}]},
        )

    @Mocker()
    def test_invalid_score_low_continue(self, mock: Mocker):
        """Test invalid captcha (score too low, but continue)"""
        self.stage.error_on_invalid_score = False
        self.stage.save()
        mock.post(
            "https://www.recaptcha.net/recaptcha/api/siteverify",
            json={
                "success": True,
                "score": -3,
            },
        )
        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()
        response = self.client.post(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
            {"token": "PASSED"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertStageRedirects(response, reverse("authentik_core:root-redirect"))

    def test_urls(self):
        """Test URLs captcha"""
        self.stage.js_url = "https://test.goauthentik.io/test.js"
        self.stage.api_url = "https://test.goauthentik.io/test"
        self.stage.save()
        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()
        response = self.client.get(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
        )
        self.assertEqual(response.status_code, 200)
        self.assertStageResponse(
            response,
            self.flow,
            js_url="https://test.goauthentik.io/test.js",
        )

    @Mocker()
    def test_upstream_failures_logged(self, mock: Mocker):
        mock.post(
            "https://www.recaptcha.net/recaptcha/api/siteverify",
            json={
                "success": False,
                "error-codes": ["invalid-input-secret"],
            },
        )
        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()
        with capture_logs() as logs:
            response = self.client.post(
                reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
                {"token": "PASSED"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertStageResponse(
            response,
            component="ak-stage-captcha",
            response_errors={"token": [{"string": "Invalid captcha response", "code": "invalid"}]},
        )

        matching_logs = [
            log
            for log in logs
            if log.event == "Failed to verify captcha token"
            and log.log_level == "warning"
        ]
        self.assertEqual(len(matching_logs), 1)

    @Mocker()
    def test_upstream_errors_logged(self, mock: Mocker):
        mock.post(
            "https://www.recaptcha.net/recaptcha/api/siteverify",
            status_code=HTTPStatus.BAD_GATEWAY,
            text="Bad Gateway",
        )
        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()
        with capture_logs() as logs:
            response = self.client.post(
                reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
                {"token": "PASSED"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertStageResponse(
            response,
            component="ak-stage-captcha",
            response_errors={"token": [{"string": "Failed to validate token", "code": "invalid"}]},
        )

        matching_logs = [
            log
            for log in logs
            if log.event == "Exception while verifying captcha token"
            and log.log_level == "warning"
        ]
        self.assertEqual(len(matching_logs), 1)
