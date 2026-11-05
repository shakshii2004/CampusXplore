from django.core.management.base import BaseCommand
from accounts.models import User, Role


class Command(BaseCommand):
    help = 'Seeds default Admin and Faculty accounts idempotently.'

    def handle(self, *args, **options):
        self.stdout.write(self.style.NOTICE('Starting staff user seeding...'))

        # 1. Admin Account
        admin_email = 'admin@lpu.in'
        admin_user = User.objects.filter(email__iexact=admin_email).first()
        if not admin_user:
            admin_user = User.objects.create_superuser(
                email=admin_email,
                password='AdminPassword123!',
                first_name='Admin',
                last_name='User'
            )
            self.stdout.write(self.style.SUCCESS(f"  + Created Admin: {admin_email}"))
        else:
            updated = False
            if admin_user.role != Role.ADMIN:
                admin_user.role = Role.ADMIN
                updated = True
            if not admin_user.is_staff:
                admin_user.is_staff = True
                updated = True
            if not admin_user.is_superuser:
                admin_user.is_superuser = True
                updated = True
            if not admin_user.check_password('AdminPassword123!'):
                admin_user.set_password('AdminPassword123!')
                updated = True
            if updated:
                admin_user.save()
                self.stdout.write(self.style.SUCCESS(f"  = Updated Admin: {admin_email}"))
            else:
                self.stdout.write(self.style.WARNING(f"  = Admin already configured: {admin_email}"))

        # 2. Faculty Account
        faculty_email = 'faculty@lpu.in'
        faculty_user = User.objects.filter(email__iexact=faculty_email).first()
        if not faculty_user:
            faculty_user = User(
                email=faculty_email,
                first_name='Faculty',
                last_name='Member',
                role=Role.FACULTY,
                is_staff=False,
                is_superuser=False,
                is_active=True
            )
            faculty_user.set_password('FacultyPassword123!')
            faculty_user.save()
            self.stdout.write(self.style.SUCCESS(f"  + Created Faculty: {faculty_email}"))
        else:
            updated = False
            if faculty_user.role != Role.FACULTY:
                faculty_user.role = Role.FACULTY
                updated = True
            if not faculty_user.check_password('FacultyPassword123!'):
                faculty_user.set_password('FacultyPassword123!')
                updated = True
            if updated:
                faculty_user.save()
                self.stdout.write(self.style.SUCCESS(f"  = Updated Faculty: {faculty_email}"))
            else:
                self.stdout.write(self.style.WARNING(f"  = Faculty already configured: {faculty_email}"))

        self.stdout.write(self.style.SUCCESS('Staff user seeding complete.'))
