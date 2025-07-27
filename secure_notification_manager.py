"""
Secure notification manager with input sanitization and enhanced error handling.
"""
import logging
import re
import smtplib
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Union, List, Optional, Any
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config_models import VMAutoscaleConfig


class NotificationError(Exception):
    """Custom exception for notification-related errors."""
    pass


class SecureNotificationManager:
    """
    Secure notification manager with enhanced security features:
    - Input sanitization to prevent injection attacks
    - Rate limiting to prevent abuse
    - Secure credential handling
    - Enhanced error handling and logging
    - Retry logic with exponential backoff
    """

    def __init__(self, config: VMAutoscaleConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        
        # Rate limiting
        self.notification_history = []
        self.max_notifications_per_hour = 60
        
        # Retry configuration
        self.retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        # HTTP session with retry logic
        self.session = requests.Session()
        adapter = HTTPAdapter(max_retries=self.retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Validate notification configuration
        self._validate_notification_config()

    def _validate_notification_config(self) -> None:
        """Validate notification configuration at startup."""
        notification_enabled = False
        
        if self.config.gotify.enabled:
            notification_enabled = True
            if not self.config.gotify.server_url or not self.config.gotify.get_app_token():
                raise NotificationError("Gotify is enabled but configuration is incomplete")
        
        if self.config.alerts.email_enabled:
            notification_enabled = True
            if not all([
                self.config.alerts.smtp_server,
                self.config.alerts.smtp_user,
                self.config.alerts.email_recipient
            ]):
                raise NotificationError("Email alerts are enabled but configuration is incomplete")

        if not notification_enabled:
            self.logger.warning("No notification method is enabled in configuration")

    def _sanitize_message(self, message: Union[str, tuple, Any]) -> str:
        """
        Sanitize message content to prevent injection attacks.
        
        Args:
            message: Message content to sanitize
            
        Returns:
            str: Sanitized message
        """
        # Convert to string if needed
        if isinstance(message, tuple):
            clean_message = ' '.join(str(part) for part in message if part)
        elif isinstance(message, str):
            clean_message = message
        else:
            clean_message = str(message)
        
        # Remove potentially dangerous characters and patterns
        clean_message = clean_message.strip()
        
        # Remove control characters except newlines and tabs
        clean_message = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', clean_message)
        
        # Limit message length to prevent DoS
        max_length = 1000
        if len(clean_message) > max_length:
            clean_message = clean_message[:max_length] + "... [truncated]"
            self.logger.warning(f"Message truncated to {max_length} characters")
        
        # Remove any remaining HTML/script tags for safety
        clean_message = re.sub(r'<[^>]*>', '', clean_message)
        
        return clean_message

    def _check_rate_limit(self) -> bool:
        """
        Check if notification rate limit is exceeded.
        
        Returns:
            bool: True if within rate limit, False otherwise
        """
        current_time = time.time()
        hour_ago = current_time - 3600
        
        # Remove old notifications
        self.notification_history = [
            timestamp for timestamp in self.notification_history 
            if timestamp > hour_ago
        ]
        
        if len(self.notification_history) >= self.max_notifications_per_hour:
            self.logger.warning("Notification rate limit exceeded")
            return False
        
        self.notification_history.append(current_time)
        return True

    def send_gotify_notification(
        self, 
        message: str, 
        priority: Optional[int] = None,
        title: str = "VM Autoscale Alert"
    ) -> None:
        """
        Send notification via Gotify with enhanced security.
        
        Args:
            message: Notification message
            priority: Notification priority (1-10)
            title: Notification title
        """
        if not self.config.gotify.enabled:
            return
        
        try:
            # Validate and sanitize inputs
            clean_message = self._sanitize_message(message)
            clean_title = self._sanitize_message(title)
            
            # Validate priority
            final_priority = priority or self.config.gotify.priority
            if not 1 <= final_priority <= 10:
                final_priority = 5
                self.logger.warning(f"Invalid priority {priority}, using default: {final_priority}")
            
            # Get configuration
            server_url = self.config.gotify.server_url.rstrip('/')
            app_token = self.config.gotify.get_app_token()
            
            if not app_token:
                raise NotificationError("Gotify app token not available")
            
            # Validate server URL
            if not server_url.startswith(('http://', 'https://')):
                raise NotificationError("Invalid Gotify server URL format")
            
            # Prepare request data
            data = {
                "title": clean_title,
                "message": clean_message,
                "priority": final_priority
            }
            
            headers = {
                "Authorization": f"Bearer {app_token}",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            # Send notification
            response = self.session.post(
                f"{server_url}/message",
                data=data,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            
            self.logger.debug("Gotify notification sent successfully")
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Failed to send Gotify notification: {str(e)}"
            self.logger.error(error_msg)
            raise NotificationError(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error sending Gotify notification: {str(e)}"
            self.logger.error(error_msg)
            raise NotificationError(error_msg)

    def send_email_notification(
        self, 
        message: str,
        subject: Optional[str] = None
    ) -> None:
        """
        Send notification via email with enhanced security.
        
        Args:
            message: Email message content
            subject: Email subject line
        """
        if not self.config.alerts.email_enabled:
            return
        
        try:
            # Sanitize inputs
            clean_message = self._sanitize_message(message)
            
            # Extract VM ID for subject if not provided
            if not subject:
                vm_match = re.search(r"VM\s+(\d+)", clean_message)
                vm_id = vm_match.group(1) if vm_match else "Unknown"
                subject = f"VM Autoscale Alert for VM {vm_id}"
            
            clean_subject = self._sanitize_message(subject)
            
            # Get SMTP configuration
            smtp_password = self.config.alerts.get_smtp_password()
            if not smtp_password:
                raise NotificationError("SMTP password not available")
            
            # Validate email recipients
            recipients = self._validate_email_recipients(self.config.alerts.email_recipient)
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = self.config.alerts.smtp_user
            msg['To'] = ", ".join(recipients)
            msg['Subject'] = clean_subject
            
            # Add message body
            msg.attach(MIMEText(clean_message, 'plain', 'utf-8'))
            
            # Send email
            with smtplib.SMTP(self.config.alerts.smtp_server, self.config.alerts.smtp_port) as server:
                server.starttls()
                server.login(self.config.alerts.smtp_user, smtp_password)
                server.sendmail(self.config.alerts.smtp_user, recipients, msg.as_string())
            
            self.logger.debug("Email notification sent successfully")
            
        except smtplib.SMTPException as e:
            error_msg = f"SMTP error sending email notification: {str(e)}"
            self.logger.error(error_msg)
            raise NotificationError(error_msg)
        except Exception as e:
            error_msg = f"Failed to send email notification: {str(e)}"
            self.logger.error(error_msg)
            raise NotificationError(error_msg)

    def _validate_email_recipients(self, recipients: Union[str, List[str]]) -> List[str]:
        """
        Validate and sanitize email recipients.
        
        Args:
            recipients: Email recipient(s)
            
        Returns:
            List[str]: Validated email addresses
        """
        if isinstance(recipients, str):
            recipient_list = [recipients]
        elif isinstance(recipients, list):
            recipient_list = recipients
        else:
            raise ValueError("Recipients must be string or list of strings")
        
        # Validate email format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        validated_recipients = []
        
        for email in recipient_list:
            if not isinstance(email, str):
                self.logger.warning(f"Skipping invalid email type: {type(email)}")
                continue
            
            email = email.strip()
            if re.match(email_pattern, email):
                validated_recipients.append(email)
            else:
                self.logger.warning(f"Skipping invalid email format: {email}")
        
        if not validated_recipients:
            raise ValueError("No valid email recipients found")
        
        return validated_recipients

    def send_notification(
        self, 
        message: Union[str, tuple, Any], 
        priority: Optional[int] = None,
        title: str = "VM Autoscale Alert"
    ) -> None:
        """
        Send notification through all configured channels.
        
        Args:
            message: Notification message
            priority: Notification priority
            title: Notification title
        """
        # Check rate limit
        if not self._check_rate_limit():
            self.logger.warning("Skipping notification due to rate limit")
            return
        
        # Sanitize message once
        clean_message = self._sanitize_message(message)
        
        if not clean_message.strip():
            self.logger.warning("Empty message after sanitization, skipping notification")
            return
        
        sent_count = 0
        errors = []
        
        # Try Gotify notification
        if self.config.gotify.enabled:
            try:
                self.send_gotify_notification(clean_message, priority, title)
                sent_count += 1
            except NotificationError as e:
                errors.append(f"Gotify: {str(e)}")
                self.logger.error(f"Gotify notification failed: {e}")
        
        # Try email notification
        if self.config.alerts.email_enabled:
            try:
                self.send_email_notification(clean_message)
                sent_count += 1
            except NotificationError as e:
                errors.append(f"Email: {str(e)}")
                self.logger.error(f"Email notification failed: {e}")
        
        # Log results
        if sent_count == 0:
            error_summary = "; ".join(errors) if errors else "No notification methods configured"
            self.logger.warning(
                f"Failed to send notification through any channel. "
                f"Message: {clean_message[:100]}... Errors: {error_summary}"
            )
        else:
            self.logger.debug(f"Notification sent through {sent_count} channel(s)")

    def __del__(self):
        """Cleanup on destruction."""
        if hasattr(self, 'session'):
            self.session.close()