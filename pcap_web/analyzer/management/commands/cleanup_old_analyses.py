# management/commands/cleanup_old_analyses.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from analyzer.models import PCAPAnalysis


class Command(BaseCommand):
    help = "Remove análises antigas e seus arquivos"

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=30,
            help="Número de dias para manter as análises (padrão: 30)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Mostra o que seria deletado sem executar",
        )

    def handle(self, *args, **options):
        days = options["days"]
        dry_run = options["dry_run"]

        cutoff_date = timezone.now() - timedelta(days=days)
        old_analyses = PCAPAnalysis.objects.filter(created_at__lt=cutoff_date)

        count = old_analyses.count()

        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    f"[DRY RUN] Seriam deletadas {count} análises anteriores a {cutoff_date.date()}"
                )
            )
            return

        if count == 0:
            self.stdout.write(self.style.SUCCESS("Nenhuma análise antiga para deletar"))
            return

        # Deletar análises (arquivos serão deletados automaticamente pelo modelo)
        deleted_count, _ = old_analyses.delete()

        self.stdout.write(
            self.style.SUCCESS(
                f"Deletadas {deleted_count} análises anteriores a {cutoff_date.date()}"
            )
        )
