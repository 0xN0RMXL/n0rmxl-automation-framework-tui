package phases

import (
	"fmt"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/config"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/phases/phase0"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/phases/phase1"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/phases/phase2"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/phases/phase3"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/phases/phase4"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/phases/phase5"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/phases/phase6"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/phases/phase7"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/phases/phase8"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/phases/phase9"
)

func JobsForPhase(phase int, target *models.Target, ws models.Workspace, runCfg *config.RunConfig) ([]*engine.Job, error) {
	switch phase {
	case 0:
		return phase0.Jobs(target, ws, runCfg), nil
	case 1:
		return phase1.Jobs(target, ws, runCfg), nil
	case 2:
		return phase2.Jobs(target, ws, runCfg), nil
	case 3:
		return phase3.Jobs(target, ws, runCfg), nil
	case 4:
		return phase4.Jobs(target, ws, runCfg), nil
	case 5:
		return phase5.Jobs(target, ws, runCfg), nil
	case 6:
		return phase6.Jobs(target, ws, runCfg), nil
	case 7:
		return phase7.Jobs(target, ws, runCfg), nil
	case 8:
		return phase8.Jobs(target, ws, runCfg), nil
	case 9:
		return phase9.Jobs(target, ws, runCfg), nil
	default:
		return nil, fmt.Errorf("invalid phase %d", phase)
	}
}

