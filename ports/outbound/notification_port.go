package outbound

const (
	EmailNotification NotificationType = 0
	SMSNotification   NotificationType = 1
)

type NotificationType int

type NotificationPort interface {
	SendNotification(address string, msg []byte) error
	SendConfirmationCode(address string, msg []byte, code string) error
}
